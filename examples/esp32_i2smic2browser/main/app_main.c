#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include "cJSON.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_websocket_client.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "base64.h"
#include "peer.h"

static const char* TAG = "webrtc";
static const int WIFI_IPV4_GOT_BIT = BIT0;
static const int WIFI_FAIL_BIT = BIT1;
#define APP_SDP_BUFFER_SIZE 8096
#define APP_SDP_BASE64_BUFFER_SIZE ((((APP_SDP_BUFFER_SIZE + 2) / 3) * 4) + 256)
#define APP_SIGNALING_RX_BUFFER_SIZE 12288
#define AUDIO_GAIN_NVS_NAMESPACE "app"
#define AUDIO_GAIN_NVS_KEY "audio_gain"

static TaskHandle_t xPcTaskHandle = NULL;
#if defined(CONFIG_BOARD_HAS_CAMERA)
static TaskHandle_t xCameraTaskHandle = NULL;
#endif
static TaskHandle_t xAudioTaskHandle = NULL;
static StaticTask_t s_audio_task_buffer;
static StackType_t s_audio_task_stack[16384];

extern esp_err_t camera_init();
extern esp_err_t audio_init();
extern esp_err_t audio_set_gain(int gain);
extern int audio_get_gain(void);
extern void camera_task(void* pvParameters);
extern void audio_task(void* pvParameters);

SemaphoreHandle_t xSemaphore = NULL;

static int64_t g_answer_applied_ms = 0;
static int64_t g_checking_ms = 0;
static int64_t g_connected_ms = 0;
static int64_t g_completed_ms = 0;
static int64_t g_dc_open_ms = 0;

PeerConnection* g_pc;
PeerConnectionState eState = PEER_CONNECTION_CLOSED;
int gDataChannelOpened = 0;
int64_t g_audio_send_enable_time = 0;
static PeerConfiguration s_peer_config = {0};
static esp_console_repl_t* s_repl = NULL;
static EventGroupHandle_t s_wifi_event_group = NULL;
static int s_wifi_retry_num = 0;
static int s_wifi_started = 0;
static int s_wifi_stopping = 0;
static volatile int s_offer_request_pending = 0;
static char s_answer_b64_buffer[APP_SDP_BASE64_BUFFER_SIZE] = {0};
static size_t s_answer_b64_len = 0;
static struct {
  char token[256];
  PeerConnection* pc;
  esp_websocket_client_handle_t ws_client;
  char rx_buffer[APP_SIGNALING_RX_BUFFER_SIZE];
  size_t rx_len;
  int offer_sent;
} s_app_signaling = {0};

static esp_err_t wifi_save_credentials(const char* ssid, const char* password);
static esp_err_t wifi_disconnect_stop(void);
static esp_err_t wifi_connect(void);
static esp_err_t audio_gain_load_from_nvs(void);
static esp_err_t audio_gain_save_to_nvs(int gain);
static int app_apply_answer_base64(const char* answer_b64);
static int app_apply_candidate_base64(const char* candidate_b64);
static void app_answer_buffer_reset(void);
static int app_answer_buffer_append_base64(const char* answer_b64_chunk);
static int app_create_offer(PeerConnection* pc, void (*onicecandidate)(char* description, void* userdata));
static int app_request_offer(void);
static PeerConnection* app_create_peer_connection_instance(void);
static int app_replace_peer_connection(void);
static int app_signaling_connect(const char* url, const char* token, PeerConnection* pc);
static void app_signaling_onicecandidate(char* description, void* userdata);
static void app_signaling_ws_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data);
static void oniceconnectionstatechange(PeerConnectionState state, void* user_data);
static void onmessage(char* msg, size_t len, void* userdata, uint16_t sid);
void onopen(void* userdata);
static void onclose(void* userdata);

int64_t get_timestamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL));
}

static void app_log_connection_snapshot(const char* reason) {
  esp_websocket_client_handle_t ws_client = s_app_signaling.ws_client;
  const char* ws_state = "closed";
  const char* pc_state = "none";

  if (ws_client != NULL) {
    switch (esp_websocket_client_is_connected(ws_client)) {
      case 0:
        ws_state = "disconnected";
        break;
      case 1:
        ws_state = "connected";
        break;
      default:
        ws_state = "unknown";
        break;
    }
  }

  if (g_pc != NULL) {
    pc_state = peer_connection_state_to_string(peer_connection_get_state(g_pc));
  }

  ESP_LOGI(TAG,
           "[STATE] reason=%s ws=%s pc=%s local_candidates=%d remote_candidates=%d offer_sent=%d answer_applied_ms=%lld",
           reason ? reason : "unknown",
           ws_state,
           pc_state,
           peer_connection_get_local_candidate_count(g_pc),
           peer_connection_get_remote_candidate_count(g_pc),
           s_app_signaling.offer_sent,
           (long long)g_answer_applied_ms);
}

static int app_lock_peer_connection(void) {
  if (xSemaphore == NULL) {
    return -1;
  }
  if (xSemaphoreTake(xSemaphore, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "failed to lock peer connection");
    return -1;
  }
  return 0;
}

static void app_unlock_peer_connection(void) {
  if (xSemaphore != NULL) {
    xSemaphoreGive(xSemaphore);
  }
}


static void app_log_offer_onicecandidate(char* description, void* userdata) {
  size_t description_len = strlen(description);
  size_t encoded_len = ((description_len + 2) / 3) * 4 + 1;
  char* encoded = NULL;

  (void)userdata;

  encoded = calloc(1, encoded_len);
  if (encoded == NULL) {
    ESP_LOGE(TAG, "failed to allocate Offer SDP base64 buffer");
    return;
  }

  ESP_LOGI(TAG, "Offer SDP:\n%s", description);
  base64_encode((const unsigned char*)description, (int)description_len, encoded, (int)encoded_len);
  ESP_LOGI(TAG, "Offer SDP Base64:\n%s", encoded);
  free(encoded);
}

static int app_create_offer(PeerConnection* pc, void (*onicecandidate)(char* description, void* userdata)) {
  if (pc == NULL || onicecandidate == NULL) {
    return -1;
  }

  if (app_lock_peer_connection() != 0) {
    ESP_LOGE(TAG, "failed to lock peer connection for offer creation");
    return -1;
  }
  peer_connection_onicecandidate(pc, onicecandidate);
  peer_connection_create_offer(pc);
  app_unlock_peer_connection();
  app_log_connection_snapshot("offer_created");
  return 0;
}

static int app_log_offer(PeerConnection* pc) {
  return app_create_offer(pc, app_log_offer_onicecandidate);
}

static int app_request_offer(void) {
  if (app_replace_peer_connection() != 0) {
    return -1;
  }

  if (s_app_signaling.pc == NULL) {
    return -1;
  }
  s_app_signaling.offer_sent = 0;
  return app_create_offer(s_app_signaling.pc, app_signaling_onicecandidate);
}

static void app_schedule_offer_request(void) {
  s_offer_request_pending = 1;
}

static PeerConnection* app_create_peer_connection_instance(void) {
  PeerConnection* pc = peer_connection_create(&s_peer_config);
  if (pc == NULL) {
    ESP_LOGE(TAG, "failed to create peer connection");
    return NULL;
  }

  peer_connection_oniceconnectionstatechange(pc, oniceconnectionstatechange);
  peer_connection_ondatachannel(pc, onmessage, onopen, onclose);
  return pc;
}

static int app_replace_peer_connection(void) {
  PeerConnection* old_pc = NULL;
  PeerConnection* new_pc = app_create_peer_connection_instance();
  if (new_pc == NULL) {
    return -1;
  }

#if defined(CONFIG_BOARD_HAS_AUDIO)
  if (xAudioTaskHandle != NULL) {
    vTaskSuspend(xAudioTaskHandle);
  }
#endif

  if (xSemaphoreTake(xSemaphore, portMAX_DELAY) != pdTRUE) {
#if defined(CONFIG_BOARD_HAS_AUDIO)
    if (xAudioTaskHandle != NULL) {
      vTaskResume(xAudioTaskHandle);
    }
#endif
    peer_connection_destroy(new_pc);
    return -1;
  }

  old_pc = g_pc;
  g_pc = new_pc;
  s_app_signaling.pc = new_pc;
  eState = PEER_CONNECTION_CLOSED;
  gDataChannelOpened = 0;
  g_audio_send_enable_time = 0;
  app_answer_buffer_reset();
  xSemaphoreGive(xSemaphore);
  app_log_connection_snapshot("peer_replaced");

#if defined(CONFIG_BOARD_HAS_AUDIO)
  if (xAudioTaskHandle != NULL) {
    vTaskResume(xAudioTaskHandle);
  }
#endif

  if (old_pc != NULL) {
    peer_connection_destroy(old_pc);
  }

  return 0;
}

static esp_err_t app_signaling_send_offer_json(const char* description) {
  cJSON* root = NULL;
  char* payload = NULL;
  char* encoded = NULL;
  size_t description_len;
  size_t encoded_len;
  int sent_len;
  esp_err_t err = ESP_FAIL;

  if (s_app_signaling.ws_client == NULL || description == NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  description_len = strlen(description);
  encoded_len = ((description_len + 2) / 3) * 4 + 1;
  encoded = calloc(1, encoded_len);
  if (encoded == NULL) {
    return ESP_ERR_NO_MEM;
  }

  base64_encode((const unsigned char*)description, (int)description_len, encoded, (int)encoded_len);

  root = cJSON_CreateObject();
  if (root == NULL) {
    err = ESP_ERR_NO_MEM;
    goto cleanup;
  }

  cJSON_AddStringToObject(root, "type", "offer");
  cJSON_AddStringToObject(root, "offer", encoded);
  cJSON_AddStringToObject(root, "source", "esp32");
  payload = cJSON_PrintUnformatted(root);
  if (payload == NULL) {
    err = ESP_ERR_NO_MEM;
    goto cleanup;
  }

  sent_len = esp_websocket_client_send_text(s_app_signaling.ws_client, payload, strlen(payload), pdMS_TO_TICKS(5000));
  if (sent_len < 0) {
    ESP_LOGE(TAG, "failed to send websocket offer");
    err = ESP_FAIL;
    goto cleanup;
  }

  s_app_signaling.offer_sent = 1;
  ESP_LOGI(TAG, "Offer SDP len=%u\n%s", (unsigned)description_len, description);
  ESP_LOGI(TAG, "Offer SDP Base64 len=%u", (unsigned)strlen(encoded));
  ESP_LOGI(TAG, "sent websocket signaling payload: %s", payload);
  err = ESP_OK;

cleanup:
  if (payload) {
    cJSON_free(payload);
  }
  if (root) {
    cJSON_Delete(root);
  }
  free(encoded);
  return err;
}

static void app_signaling_onicecandidate(char* description, void* userdata) {
  (void)userdata;

  ESP_ERROR_CHECK_WITHOUT_ABORT(app_signaling_send_offer_json(description));
}

static void app_signaling_process_message(const char* message, size_t length) {
  cJSON* root = NULL;
  cJSON* answer = NULL;
  cJSON* candidate = NULL;
  cJSON* candidate_b64 = NULL;
  cJSON* log_item = NULL;
  cJSON* request = NULL;
  cJSON* request_offer = NULL;
  char* text = NULL;

  text = calloc(1, length + 1);
  if (text == NULL) {
    ESP_LOGE(TAG, "failed to allocate websocket message buffer");
    return;
  }

  memcpy(text, message, length);
  text[length] = '\0';
  ESP_LOGI(TAG, "received websocket signaling payload: %s", text);

  root = cJSON_Parse(text);
  if (root == NULL) {
    ESP_LOGE(TAG, "failed to parse websocket signaling json");
    goto cleanup;
  }

  request_offer = cJSON_GetObjectItemCaseSensitive(root, "request_offer");
  request = cJSON_GetObjectItemCaseSensitive(root, "request");
  if ((cJSON_IsBool(request_offer) && cJSON_IsTrue(request_offer)) ||
      (cJSON_IsString(request) && request->valuestring != NULL && strcmp(request->valuestring, "offer") == 0)) {
    ESP_LOGI(TAG, "received websocket offer request");
    app_schedule_offer_request();
    app_log_connection_snapshot("offer_requested");
    goto cleanup;
  }

  candidate_b64 = cJSON_GetObjectItemCaseSensitive(root, "candidate_b64");
  if (cJSON_IsString(candidate_b64) && candidate_b64->valuestring != NULL && candidate_b64->valuestring[0] != '\0') {
    ESP_LOGI(TAG, "received websocket remote candidate_b64");
    if (app_apply_candidate_base64(candidate_b64->valuestring) != 0) {
      ESP_LOGE(TAG, "failed to add remote ICE candidate from base64");
    }
    app_log_connection_snapshot("candidate_received");
    goto cleanup;
  }

  candidate = cJSON_GetObjectItemCaseSensitive(root, "candidate");
  if (cJSON_IsString(candidate) && candidate->valuestring != NULL && candidate->valuestring[0] != '\0') {
    ESP_LOGI(TAG, "received websocket remote candidate");
    if (app_lock_peer_connection() == 0) {
      if (peer_connection_add_ice_candidate(g_pc, candidate->valuestring) != 0) {
        ESP_LOGE(TAG, "failed to add remote ICE candidate");
      }
      app_unlock_peer_connection();
    }
    app_log_connection_snapshot("candidate_received");
    goto cleanup;
  }

  log_item = cJSON_GetObjectItemCaseSensitive(root, "log");
  if (cJSON_IsString(log_item) && log_item->valuestring != NULL && log_item->valuestring[0] != '\0') {
    ESP_LOGI(TAG, "remote log: %s", log_item->valuestring);
    goto cleanup;
  }

  answer = cJSON_GetObjectItemCaseSensitive(root, "answer");
  if (!cJSON_IsString(answer) || answer->valuestring == NULL || answer->valuestring[0] == '\0') {
    ESP_LOGW(TAG, "websocket signaling json does not contain answer");
    goto cleanup;
  }

  if (app_apply_answer_base64(answer->valuestring) != 0) {
    ESP_LOGE(TAG, "failed to apply Answer SDP from websocket json");
    goto cleanup;
  }

  ESP_LOGI(TAG, "Answer SDP applied from websocket");
  app_log_connection_snapshot("answer_applied");

cleanup:
  if (root) {
    cJSON_Delete(root);
  }
  free(text);
}

static void app_signaling_ws_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data) {
  esp_websocket_event_data_t* data = (esp_websocket_event_data_t*)event_data;
  (void)handler_args;
  (void)base;

  switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
      ESP_LOGI(TAG, "websocket signaling connected");
      s_app_signaling.rx_len = 0;
      s_app_signaling.offer_sent = 0;
      app_log_connection_snapshot("ws_connected");
      app_schedule_offer_request();
      break;
    case WEBSOCKET_EVENT_DATA:
      if (data == NULL || data->data_ptr == NULL || data->data_len <= 0) {
        break;
      }

      if ((size_t)data->payload_offset == 0) {
        s_app_signaling.rx_len = 0;
      }

      if ((size_t)data->payload_offset + data->data_len + 1 > sizeof(s_app_signaling.rx_buffer)) {
        ESP_LOGE(TAG, "websocket signaling message is too large");
        s_app_signaling.rx_len = 0;
        break;
      }

      memcpy(s_app_signaling.rx_buffer + data->payload_offset, data->data_ptr, data->data_len);
      s_app_signaling.rx_len = (size_t)data->payload_offset + data->data_len;
      s_app_signaling.rx_buffer[s_app_signaling.rx_len] = '\0';

      if ((size_t)data->payload_offset + data->data_len >= (size_t)data->payload_len) {
        app_signaling_process_message(s_app_signaling.rx_buffer, s_app_signaling.rx_len);
        s_app_signaling.rx_len = 0;
      }
      break;
    case WEBSOCKET_EVENT_DISCONNECTED:
      ESP_LOGW(TAG, "websocket signaling disconnected");
      app_log_connection_snapshot("ws_disconnected");
      break;
    case WEBSOCKET_EVENT_ERROR:
      ESP_LOGE(TAG, "websocket signaling error");
      app_log_connection_snapshot("ws_error");
      break;
    default:
      break;
  }
}

static int app_signaling_connect(const char* url, const char* token, PeerConnection* pc) {
  esp_websocket_client_config_t ws_cfg = {
      .uri = url,
      .network_timeout_ms = 10000,
      .task_stack = 8192,
      .skip_cert_common_name_check = true,
  };

  memset(&s_app_signaling, 0, sizeof(s_app_signaling));

  if (token != NULL && strlen(token) > 0) {
    strncpy(s_app_signaling.token, token, sizeof(s_app_signaling.token) - 1);
  }
  s_app_signaling.pc = pc;

  s_app_signaling.ws_client = esp_websocket_client_init(&ws_cfg);
  if (s_app_signaling.ws_client == NULL) {
    ESP_LOGE(TAG, "failed to create websocket signaling client");
    return -1;
  }

  ESP_ERROR_CHECK_WITHOUT_ABORT(esp_websocket_register_events(s_app_signaling.ws_client,
                                                              WEBSOCKET_EVENT_ANY,
                                                              app_signaling_ws_event_handler,
                                                              NULL));

  ESP_LOGI(TAG, "app signaling url: %s", url);
  if (esp_websocket_client_start(s_app_signaling.ws_client) != ESP_OK) {
    ESP_LOGE(TAG, "failed to start websocket signaling client");
    esp_websocket_client_destroy(s_app_signaling.ws_client);
    s_app_signaling.ws_client = NULL;
    return -1;
  }
  return 0;
}

static int app_apply_answer_base64(const char* answer_b64) {
  size_t input_len;
  size_t decoded_capacity;
  unsigned char* decoded = NULL;
  int decoded_len;

  if (g_pc == NULL || answer_b64 == NULL || answer_b64[0] == '\0') {
    return -1;
  }

  input_len = strlen(answer_b64);
  decoded_capacity = (input_len / 4) * 3 + 4;
  if (decoded_capacity < APP_SDP_BUFFER_SIZE) {
    decoded_capacity = APP_SDP_BUFFER_SIZE;
  }

  decoded = calloc(1, decoded_capacity);
  if (decoded == NULL) {
    ESP_LOGE(TAG, "failed to allocate Answer SDP decode buffer");
    return -1;
  }

  decoded_len = base64_decode(answer_b64, (int)input_len, decoded, (int)(decoded_capacity - 1));
  if (decoded_len <= 0) {
    ESP_LOGE(TAG, "failed to decode Answer SDP base64");
    free(decoded);
    return -1;
  }

  decoded[decoded_len] = '\0';
  ESP_LOGI(TAG, "Decoded Answer SDP:\n%s", decoded);
  if (app_lock_peer_connection() != 0) {
    ESP_LOGE(TAG, "failed to lock peer connection for Answer apply");
    free(decoded);
    return -1;
  }
  g_answer_applied_ms = get_timestamp();
  ESP_LOGI(TAG, "[TIMING] answer_apply_start=%lld", g_answer_applied_ms);

  peer_connection_set_remote_description(g_pc, (const char*)decoded, SDP_TYPE_ANSWER);

  ESP_LOGI(TAG, "[TIMING] answer_apply_done=%lld delta=%lldms",
          get_timestamp(),
          get_timestamp() - g_answer_applied_ms);
  app_unlock_peer_connection();
  ESP_LOGI(TAG, "applied Answer SDP from base64, decoded length: %d", decoded_len);
  free(decoded);
  return 0;
}

static int app_apply_candidate_base64(const char* candidate_b64) {
  size_t input_len;
  size_t decoded_capacity;
  unsigned char* decoded = NULL;
  int decoded_len;

  if (g_pc == NULL || candidate_b64 == NULL || candidate_b64[0] == '\0') {
    return -1;
  }

  input_len = strlen(candidate_b64);
  decoded_capacity = (input_len / 4) * 3 + 4;
  if (decoded_capacity < 256) {
    decoded_capacity = 256;
  }

  decoded = calloc(1, decoded_capacity);
  if (decoded == NULL) {
    ESP_LOGE(TAG, "failed to allocate ICE candidate decode buffer");
    return -1;
  }

  decoded_len = base64_decode(candidate_b64, (int)input_len, decoded, (int)(decoded_capacity - 1));
  if (decoded_len <= 0) {
    ESP_LOGE(TAG, "failed to decode ICE candidate base64");
    free(decoded);
    return -1;
  }

  decoded[decoded_len] = '\0';
  ESP_LOGI(TAG, "Decoded ICE candidate: %s", decoded);

  if (app_lock_peer_connection() != 0) {
    free(decoded);
    return -1;
  }

  if (peer_connection_add_ice_candidate(g_pc, (char*)decoded) != 0) {
    ESP_LOGE(TAG, "failed to add ICE candidate from base64");
    app_unlock_peer_connection();
    free(decoded);
    return -1;
  }

  app_unlock_peer_connection();
  free(decoded);
  return 0;
}

static void app_answer_buffer_reset(void) {
  memset(s_answer_b64_buffer, 0, sizeof(s_answer_b64_buffer));
  s_answer_b64_len = 0;
}

static int app_answer_buffer_append_base64(const char* answer_b64_chunk) {
  size_t chunk_len;

  if (answer_b64_chunk == NULL || answer_b64_chunk[0] == '\0') {
    return -1;
  }

  chunk_len = strlen(answer_b64_chunk);
  if (s_answer_b64_len + chunk_len + 1 > sizeof(s_answer_b64_buffer)) {
    ESP_LOGE(TAG, "answer base64 buffer is too small");
    return -1;
  }

  memcpy(s_answer_b64_buffer + s_answer_b64_len, answer_b64_chunk, chunk_len);
  s_answer_b64_len += chunk_len;
  s_answer_b64_buffer[s_answer_b64_len] = '\0';
  return 0;
}


static int console_reset_cmd(int argc, char** argv) {
  (void)argc;
  (void)argv;

  ESP_LOGI(TAG, "Restarting via console command");
  esp_restart();
  return 0;
}

static int console_wifi_set_cmd(int argc, char** argv) {
  esp_err_t err;

  if (argc != 3) {
    ESP_LOGE(TAG, "usage: wifi_set <ssid> <password>");
    return 1;
  }

  err = wifi_save_credentials(argv[1], argv[2]);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to save Wi-Fi credentials: %s", esp_err_to_name(err));
    return 1;
  }

  ESP_LOGI(TAG, "saved Wi-Fi credentials for SSID: %s", argv[1]);
  return 0;
}

static int console_wifi_discon_cmd(int argc, char** argv) {
  esp_err_t err;

  if (argc != 1) {
    ESP_LOGE(TAG, "usage: wifidiscon");
    return 1;
  }

  err = wifi_disconnect_stop();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to disconnect Wi-Fi: %s", esp_err_to_name(err));
    return 1;
  }

  ESP_LOGI(TAG, "Wi-Fi disconnected");
  return 0;
}

static int console_wifi_reconn_cmd(int argc, char** argv) {
  esp_err_t err;

  if (argc != 1) {
    ESP_LOGE(TAG, "usage: wifireconn");
    return 1;
  }

  err = wifi_connect();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to reconnect Wi-Fi: %s", esp_err_to_name(err));
    return 1;
  }

  ESP_LOGI(TAG, "Wi-Fi reconnect started");
  return 0;
}

static int console_wifi_conn_cmd(int argc, char** argv) {
  esp_err_t err;

  if (argc != 1 && argc != 3) {
    ESP_LOGE(TAG, "usage: wificonn [ssid password]");
    return 1;
  }

  if (argc == 3) {
    err = wifi_save_credentials(argv[1], argv[2]);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "failed to save Wi-Fi credentials: %s", esp_err_to_name(err));
      return 1;
    }
  }

  err = wifi_disconnect_stop();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to reset Wi-Fi state: %s", esp_err_to_name(err));
    return 1;
  }

  err = wifi_connect();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to connect Wi-Fi: %s", esp_err_to_name(err));
    return 1;
  }

  ESP_LOGI(TAG, "Wi-Fi connection started");
  return 0;
}

static int console_answer_set_b64_cmd(int argc, char** argv) {
  if (argc != 2) {
    ESP_LOGE(TAG, "usage: answer_set_b64 <base64>");
    return 1;
  }

  if (app_apply_answer_base64(argv[1]) != 0) {
    ESP_LOGE(TAG, "failed to apply Answer SDP from base64");
    return 1;
  }

  ESP_LOGI(TAG, "Answer SDP applied");
  return 0;
}

static int console_answer_begin_cmd(int argc, char** argv) {
  if (argc != 1) {
    ESP_LOGE(TAG, "usage: answer_begin");
    return 1;
  }

  app_answer_buffer_reset();
  ESP_LOGI(TAG, "Answer SDP base64 buffer reset");
  return 0;
}

static int console_answer_append_b64_cmd(int argc, char** argv) {
  if (argc != 2) {
    ESP_LOGE(TAG, "usage: answer_append_b64 <base64_chunk>");
    return 1;
  }

  if (app_answer_buffer_append_base64(argv[1]) != 0) {
    ESP_LOGE(TAG, "failed to append Answer SDP base64 chunk");
    return 1;
  }

  ESP_LOGI(TAG, "Answer SDP base64 chunk appended, total length: %u", (unsigned)s_answer_b64_len);
  return 0;
}

static int console_answer_apply_cmd(int argc, char** argv) {
  if (argc != 1) {
    ESP_LOGE(TAG, "usage: answer_apply");
    return 1;
  }

  if (s_answer_b64_len == 0) {
    ESP_LOGE(TAG, "Answer SDP base64 buffer is empty");
    return 1;
  }

  if (app_apply_answer_base64(s_answer_b64_buffer) != 0) {
    ESP_LOGE(TAG, "failed to apply buffered Answer SDP base64");
    return 1;
  }

  ESP_LOGI(TAG, "Buffered Answer SDP applied");
  return 0;
}

static int console_audio_gain_cmd(int argc, char** argv) {
  long gain_value;
  esp_err_t err;
  char* endptr = NULL;

  if (argc == 1) {
    ESP_LOGI(TAG, "current audio gain: %d", audio_get_gain());
    return 0;
  }

  if (argc != 2) {
    ESP_LOGE(TAG, "usage: audiogain [1-64]");
    return 1;
  }

  gain_value = strtol(argv[1], &endptr, 10);
  if (endptr == argv[1] || *endptr != '\0' || gain_value < 1 || gain_value > 64) {
    ESP_LOGE(TAG, "audio gain must be in range 1..64");
    return 1;
  }

  err = audio_set_gain((int)gain_value);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to apply audio gain: %s", esp_err_to_name(err));
    return 1;
  }

  err = audio_gain_save_to_nvs((int)gain_value);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to save audio gain: %s", esp_err_to_name(err));
    return 1;
  }

  ESP_LOGI(TAG, "audio gain saved: %ld", gain_value);
  return 0;
}

static void console_init(void) {
  esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
  esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();

  repl_config.prompt = "peer> ";

  ESP_ERROR_CHECK(esp_console_register_help_command());

  const esp_console_cmd_t reset_cmd = {
      .command = "reset",
      .help = "Restart the device",
      .hint = NULL,
      .func = &console_reset_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&reset_cmd));

  const esp_console_cmd_t wifi_set_cmd = {
      .command = "wifi_set",
      .help = "Save Wi-Fi credentials to NVS: wifi_set <ssid> <password>",
      .hint = NULL,
      .func = &console_wifi_set_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_set_cmd));

  const esp_console_cmd_t wifi_discon_cmd = {
      .command = "wifidiscon",
      .help = "Disconnect Wi-Fi and stop STA",
      .hint = NULL,
      .func = &console_wifi_discon_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_discon_cmd));

  const esp_console_cmd_t wifi_reconn_cmd = {
      .command = "wifireconn",
      .help = "Reconnect Wi-Fi using saved/default credentials",
      .hint = NULL,
      .func = &console_wifi_reconn_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_reconn_cmd));

  const esp_console_cmd_t wifi_conn_cmd = {
      .command = "wificonn",
      .help = "Connect Wi-Fi using saved/default config or save new credentials: wificonn [ssid password]",
      .hint = NULL,
      .func = &console_wifi_conn_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_conn_cmd));

  const esp_console_cmd_t answer_set_b64_cmd = {
      .command = "answer_set_b64",
      .help = "Apply Answer SDP from base64: answer_set_b64 <base64>",
      .hint = NULL,
      .func = &console_answer_set_b64_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&answer_set_b64_cmd));

  const esp_console_cmd_t answer_begin_cmd = {
      .command = "answer_begin",
      .help = "Reset buffered Answer SDP base64",
      .hint = NULL,
      .func = &console_answer_begin_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&answer_begin_cmd));

  const esp_console_cmd_t answer_append_b64_cmd = {
      .command = "answer_append_b64",
      .help = "Append Answer SDP base64 chunk: answer_append_b64 <base64_chunk>",
      .hint = NULL,
      .func = &console_answer_append_b64_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&answer_append_b64_cmd));

  const esp_console_cmd_t answer_apply_cmd = {
      .command = "answer_apply",
      .help = "Apply buffered Answer SDP base64",
      .hint = NULL,
      .func = &console_answer_apply_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&answer_apply_cmd));

  const esp_console_cmd_t audio_gain_cmd = {
      .command = "audiogain",
      .help = "Show or set audio gain and save to NVS: audiogain [1-64]",
      .hint = NULL,
      .func = &console_audio_gain_cmd,
      .argtable = NULL,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&audio_gain_cmd));

  ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &s_repl));
  ESP_ERROR_CHECK(esp_console_start_repl(s_repl));
}

static esp_err_t audio_gain_load_from_nvs(void) {
  nvs_handle_t nvs_handle;
  int32_t saved_gain = 0;
  esp_err_t err = nvs_open(AUDIO_GAIN_NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    return ESP_ERR_NOT_FOUND;
  }
  if (err != ESP_OK) {
    return err;
  }

  err = nvs_get_i32(nvs_handle, AUDIO_GAIN_NVS_KEY, &saved_gain);
  nvs_close(nvs_handle);
  if (err != ESP_OK) {
    return err;
  }

  return audio_set_gain((int)saved_gain);
}

static esp_err_t audio_gain_save_to_nvs(int gain) {
  nvs_handle_t nvs_handle;
  esp_err_t err = nvs_open(AUDIO_GAIN_NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK) {
    return err;
  }

  err = nvs_set_i32(nvs_handle, AUDIO_GAIN_NVS_KEY, gain);
  if (err == ESP_OK) {
    err = nvs_commit(nvs_handle);
  }
  nvs_close(nvs_handle);
  return err;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
  (void)arg;
  (void)event_data;

  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    xEventGroupClearBits(s_wifi_event_group, WIFI_IPV4_GOT_BIT);

    if (s_wifi_stopping) {
      return;
    }

    if (s_wifi_retry_num < CONFIG_DEFAULT_WIFI_MAXIMUM_RETRY) {
      esp_wifi_connect();
      s_wifi_retry_num++;
      ESP_LOGI(TAG, "retrying Wi-Fi connection");
    } else {
      xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    }
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
    s_wifi_retry_num = 0;
    ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(s_wifi_event_group, WIFI_IPV4_GOT_BIT);
  }
}

static esp_err_t wifi_save_credentials(const char* ssid, const char* password) {
  wifi_config_t wifi_config = {0};
  esp_err_t err;

  if (ssid == NULL || strlen(ssid) == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
  if (password) {
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));
  }

  wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  wifi_config.sta.pmf_cfg.capable = true;
  wifi_config.sta.pmf_cfg.required = false;

  if (password == NULL || strlen(password) == 0) {
    wifi_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
  }

  err = esp_wifi_set_storage(WIFI_STORAGE_FLASH);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to set Wi-Fi storage");
    return err;
  }

  return esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
}

static esp_err_t wifi_disconnect_stop(void) {
  esp_err_t err;

  if (!s_wifi_started) {
    return ESP_OK;
  }

  s_wifi_stopping = 1;
  s_wifi_retry_num = 0;
  xEventGroupClearBits(s_wifi_event_group, WIFI_IPV4_GOT_BIT | WIFI_FAIL_BIT);

  err = esp_wifi_disconnect();
  if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_STARTED && err != ESP_ERR_WIFI_NOT_INIT && err != ESP_ERR_WIFI_CONN) {
    s_wifi_stopping = 0;
    return err;
  }

  err = esp_wifi_stop();
  if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_STARTED && err != ESP_ERR_WIFI_NOT_INIT) {
    s_wifi_stopping = 0;
    return err;
  }

  s_wifi_started = 0;
  s_wifi_stopping = 0;
  ESP_LOGI(TAG, "Wi-Fi STA stopped");
  return ESP_OK;
}

static esp_err_t wifi_connect(void) {
  wifi_config_t wifi_config = {0};
  esp_err_t err;

  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  s_wifi_stopping = 0;
  s_wifi_retry_num = 0;
  xEventGroupClearBits(s_wifi_event_group, WIFI_IPV4_GOT_BIT | WIFI_FAIL_BIT);

  err = esp_wifi_get_config(WIFI_IF_STA, &wifi_config);
  if (err != ESP_OK) {
    return err;
  }

  if (strlen((const char*)wifi_config.sta.ssid) == 0) {
    if (strlen(CONFIG_DEFAULT_WIFI_SSID) == 0) {
      return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "no saved Wi-Fi config, using default config");
    err = wifi_save_credentials(CONFIG_DEFAULT_WIFI_SSID, CONFIG_DEFAULT_WIFI_PASSWORD);
    if (err != ESP_OK) {
      return err;
    }

    err = esp_wifi_get_config(WIFI_IF_STA, &wifi_config);
    if (err != ESP_OK) {
      return err;
    }
  }

  err = esp_wifi_start();
  if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
    return err;
  }

  s_wifi_started = 1;
  ESP_LOGI(TAG, "starting Wi-Fi connection to AP: %s", wifi_config.sta.ssid);
  return ESP_OK;
}

static void wifi_init_sta(void) {
  esp_netif_t* sta_netif = NULL;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

  s_wifi_event_group = xEventGroupCreate();
  if (s_wifi_event_group == NULL) {
    ESP_LOGE(TAG, "failed to create Wi-Fi event group");
    abort();
  }

  sta_netif = esp_netif_create_default_wifi_sta();
  assert(sta_netif != NULL);

  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                             ESP_EVENT_ANY_ID,
                                             &wifi_event_handler,
                                             NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,
                                             IP_EVENT_STA_GOT_IP,
                                             &wifi_event_handler,
                                             NULL));
}

static void oniceconnectionstatechange(PeerConnectionState state, void* user_data) {
  int64_t now = get_timestamp();

  if (state == PEER_CONNECTION_CHECKING) {
    g_checking_ms = now;
    ESP_LOGI(TAG, "[TIMING] state=CHECKING at=%lld from_answer=%lldms",
             now, now - g_answer_applied_ms);
  } else if (state == PEER_CONNECTION_CONNECTED) {
    g_connected_ms = now;
    ESP_LOGI(TAG, "[TIMING] state=CONNECTED at=%lld from_answer=%lldms from_checking=%lldms",
             now,
             now - g_answer_applied_ms,
             g_checking_ms ? now - g_checking_ms : -1);
  } else if (state == PEER_CONNECTION_COMPLETED) {
    g_completed_ms = now;
    ESP_LOGI(TAG, "[TIMING] state=COMPLETED at=%lld from_answer=%lldms from_connected=%lldms",
             now,
             now - g_answer_applied_ms,
             g_connected_ms ? now - g_connected_ms : -1);
  } else {
    ESP_LOGI(TAG, "[TIMING] state=%d at=%lld from_answer=%lldms",
             state, now,
             g_answer_applied_ms ? now - g_answer_applied_ms : -1);
  }

  ESP_LOGI(TAG, "PeerConnectionState: %d", state);
  eState = state;

  if (state == PEER_CONNECTION_COMPLETED) {
    g_audio_send_enable_time = get_timestamp();
  } else {
    g_audio_send_enable_time = 0;
  }

  if (eState != PEER_CONNECTION_COMPLETED) {
    gDataChannelOpened = 0;
  }

  app_log_connection_snapshot("ice_state_changed");
}

static void onmessage(char* msg, size_t len, void* userdata, uint16_t sid) {
  ESP_LOGI(TAG, "Datachannel message: %.*s", len, msg);
}

void onopen(void* userdata) {
  g_dc_open_ms = get_timestamp();
  ESP_LOGI(TAG, "[TIMING] datachannel_open at=%lld from_answer=%lldms from_completed=%lldms",
           g_dc_open_ms,
           g_answer_applied_ms ? g_dc_open_ms - g_answer_applied_ms : -1,
           g_completed_ms ? g_dc_open_ms - g_completed_ms : -1);
  ESP_LOGI(TAG, "Datachannel opened");
  gDataChannelOpened = 1;
  app_log_connection_snapshot("datachannel_opened");
}
static void onclose(void* userdata) {
  ESP_LOGW(TAG, "Datachannel closed");
  gDataChannelOpened = 0;
  app_log_connection_snapshot("datachannel_closed");
}

void peer_connection_task(void* arg) {
  ESP_LOGI(TAG, "peer_connection_task started");

  for (;;) {
    if (xSemaphoreTake(xSemaphore, portMAX_DELAY)) {
      peer_connection_loop(g_pc);
      xSemaphoreGive(xSemaphore);
    }

    vTaskDelay(pdMS_TO_TICKS(1));
  }
}

void app_main(void) {
  s_peer_config = (PeerConfiguration){
      .ice_servers = {{0}},
#if defined(CONFIG_AUDIO_CODEC_OPUS)
      .audio_codec = CODEC_OPUS,
#else
      .audio_codec = CODEC_PCMA,
#endif
      .datachannel = DATA_CHANNEL_BINARY,
  };

  #if defined(CONFIG_USE_TURN_SERVER) && CONFIG_USE_TURN_SERVER
  if (strlen(CONFIG_TURN_SERVER_URL) > 0) {
    s_peer_config.ice_servers[0].urls = CONFIG_TURN_SERVER_URL;
  #if defined(CONFIG_TURN_SERVER_USERNAME)
    s_peer_config.ice_servers[0].username = CONFIG_TURN_SERVER_USERNAME;
  #endif
  #if defined(CONFIG_TURN_SERVER_CREDENTIAL)
    s_peer_config.ice_servers[0].credential = CONFIG_TURN_SERVER_CREDENTIAL;
  #endif
  }
  #else
  s_peer_config.ice_servers[0].urls = "stun:stun1.l.google.com:3478";
  #endif

  ESP_LOGI(TAG, "[APP] Startup..");
  ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
  ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

  esp_log_level_set("*", ESP_LOG_INFO);
  esp_log_level_set("esp-tls", ESP_LOG_VERBOSE);
  esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
  esp_log_level_set("MQTT_EXAMPLE", ESP_LOG_VERBOSE);
  esp_log_level_set("TRANSPORT_BASE", ESP_LOG_VERBOSE);
  esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
  esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);

  console_init();

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_sta();
  ESP_ERROR_CHECK(wifi_connect());

  xSemaphore = xSemaphoreCreateMutex();

  peer_init();

#if defined(CONFIG_BOARD_HAS_CAMERA)
  camera_init();
#endif

#if defined(CONFIG_BOARD_HAS_AUDIO)
  audio_init();
  esp_err_t audio_gain_err = audio_gain_load_from_nvs();
  if (audio_gain_err == ESP_OK) {
    ESP_LOGI(TAG, "loaded audio gain from NVS: %d", audio_get_gain());
  } else if (audio_gain_err == ESP_ERR_NOT_FOUND) {
    ESP_LOGI(TAG, "using default audio gain: %d", audio_get_gain());
  } else {
    ESP_LOGW(TAG, "failed to load audio gain from NVS: %s", esp_err_to_name(audio_gain_err));
  }
#endif

  xEventGroupWaitBits(s_wifi_event_group,
                      WIFI_IPV4_GOT_BIT,
                      pdFALSE,
                      pdFALSE,
                      portMAX_DELAY);

  g_pc = app_create_peer_connection_instance();
  assert(g_pc != NULL);
  s_app_signaling.pc = g_pc;
  app_signaling_connect(CONFIG_SIGNALING_URL, CONFIG_SIGNALING_TOKEN, g_pc);

#if defined(CONFIG_BOARD_HAS_AUDIO)
  xAudioTaskHandle = xTaskCreateStaticPinnedToCore(audio_task,
                                                   "audio",
                                                   16384,
                                                   NULL,
                                                   7,
                                                   s_audio_task_stack,
                                                   &s_audio_task_buffer,
                                                   0);
  assert(xAudioTaskHandle != NULL);
#endif

#if defined(CONFIG_BOARD_HAS_CAMERA)
  xTaskCreatePinnedToCore(camera_task, "camera", 4096, NULL, 8, &xCameraTaskHandle, 1);
#endif

  xTaskCreatePinnedToCore(peer_connection_task, "peer_connection", 16384, NULL, 5, &xPcTaskHandle, 1);

  ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
  printf("============= Configuration =============\n");
  printf(" %-5s : %s\n", "URL", CONFIG_SIGNALING_URL);
  printf(" %-5s : %s\n", "Token", CONFIG_SIGNALING_TOKEN);
  printf("=========================================\n");

  while (1) {
    if (s_offer_request_pending) {
      s_offer_request_pending = 0;
      if (app_request_offer() != 0) {
        ESP_LOGE(TAG, "failed to create requested Offer SDP");
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
