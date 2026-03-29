#include "driver/i2s_pdm.h"
#include "driver/i2s_std.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_audio_enc.h"
#include "esp_audio_enc_default.h"
#include "esp_audio_enc_reg.h"
#include "esp_g711_enc.h"
#include "esp_opus_enc.h"

#include "peer.h"

#ifndef CONFIG_AUDIO_PDM_CLK_GPIO
#define CONFIG_AUDIO_PDM_CLK_GPIO 42
#endif

#ifndef CONFIG_AUDIO_PDM_DATA_GPIO
#define CONFIG_AUDIO_PDM_DATA_GPIO 41
#endif

static const char* TAG = "AUDIO";

extern PeerConnection* g_pc;
extern PeerConnectionState eState;
extern int64_t get_timestamp();
extern int64_t g_audio_send_enable_time;
extern SemaphoreHandle_t xSemaphore;

i2s_chan_handle_t rx_handle = NULL;
static uint8_t* raw_i2s_buf = NULL;
static size_t raw_i2s_buf_size = 0;
static volatile int s_audio_input_gain = CONFIG_AUDIO_INPUT_GAIN;

esp_audio_enc_handle_t enc_handle = NULL;
esp_audio_enc_in_frame_t aenc_in_frame = {0};
esp_audio_enc_out_frame_t aenc_out_frame = {0};
esp_g711_enc_config_t g711_cfg;
esp_opus_enc_config_t opus_cfg;
esp_audio_enc_config_t enc_cfg;

#if !defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
static esp_err_t pdm_audio_init(void);
static void pdm_audio_deinit(void);
static int32_t pdm_audio_get_samples(uint8_t* buf, size_t size);
#endif
static esp_err_t msm261_audio_init(void);
static void msm261_audio_deinit(void);
static int32_t msm261_audio_get_samples(uint8_t* buf, size_t size);
static esp_err_t msm261_enable_chip(void);
static void msm261_disable_chip(void);

static esp_err_t audio_input_init(void);
static void audio_input_deinit(void);
static int32_t audio_input_get_samples(uint8_t* buf, size_t size);
static void audio_apply_gain(int16_t* samples, size_t sample_count);

static void audio_apply_gain(int16_t* samples, size_t sample_count) {
  int gain = s_audio_input_gain;

  if (gain <= 1) {
    return;
  }

  for (size_t i = 0; i < sample_count; i++) {
    int32_t scaled = (int32_t)samples[i] * gain;
    if (scaled > INT16_MAX) {
      scaled = INT16_MAX;
    } else if (scaled < INT16_MIN) {
      scaled = INT16_MIN;
    }
    samples[i] = (int16_t)scaled;
  }
}

esp_err_t audio_codec_init() {
  uint8_t* read_buf = NULL;
  uint8_t* write_buf = NULL;
  int read_size = 0;
  int out_size = 0;

  esp_audio_err_t ret = ESP_AUDIO_ERR_OK;
  const char* codec_name = "unknown";

  esp_audio_enc_register_default();

  memset(&enc_cfg, 0, sizeof(enc_cfg));

#if defined(CONFIG_AUDIO_CODEC_OPUS)
  opus_cfg = (esp_opus_enc_config_t)ESP_OPUS_ENC_CONFIG_DEFAULT();
  opus_cfg.sample_rate = ESP_AUDIO_SAMPLE_RATE_8K;
  opus_cfg.channel = ESP_AUDIO_MONO;
  opus_cfg.bits_per_sample = ESP_AUDIO_BIT16;
  opus_cfg.bitrate = ESP_OPUS_BITRATE_AUTO;
  opus_cfg.frame_duration = ESP_OPUS_ENC_FRAME_DURATION_20_MS;
  opus_cfg.application_mode = ESP_OPUS_ENC_APPLICATION_VOIP;
  opus_cfg.enable_vbr = true;

  enc_cfg.type = ESP_AUDIO_TYPE_OPUS;
  enc_cfg.cfg = &opus_cfg;
  enc_cfg.cfg_sz = sizeof(opus_cfg);
  codec_name = "opus";
#else
  g711_cfg = (esp_g711_enc_config_t)ESP_G711_ENC_CONFIG_DEFAULT();
  g711_cfg.sample_rate = ESP_AUDIO_SAMPLE_RATE_8K;
  g711_cfg.channel = ESP_AUDIO_MONO;
  g711_cfg.bits_per_sample = ESP_AUDIO_BIT16;
  g711_cfg.frame_duration = 20;

  enc_cfg.type = ESP_AUDIO_TYPE_G711A;
  enc_cfg.cfg = &g711_cfg;
  enc_cfg.cfg_sz = sizeof(g711_cfg);
  codec_name = "g711a";
#endif

  ret = esp_audio_enc_open(&enc_cfg, &enc_handle);
  if (ret != ESP_AUDIO_ERR_OK) {
    ESP_LOGE(TAG, "audio encoder open failed: %d", ret);
    return ESP_FAIL;
  }

  int frame_size = 0;
#if defined(CONFIG_AUDIO_CODEC_OPUS)
  frame_size = (opus_cfg.bits_per_sample * opus_cfg.channel) >> 3;
#else
  frame_size = (g711_cfg.bits_per_sample * g711_cfg.channel) >> 3;
#endif
  // Get frame_size
  esp_audio_enc_get_frame_size(enc_handle, &read_size, &out_size);
  ESP_LOGI(TAG, "audio codec init. codec: %s frame size: %d, read size: %d, out size: %d",
           codec_name, frame_size, read_size, out_size);
  // 8000HZ duration 20ms
  if (frame_size == read_size) {
    read_size *= 8000 / 1000 * 20;
    out_size *= 8000 / 1000 * 20;
  }
  read_buf = malloc(read_size);
  write_buf = malloc(out_size);
  if (read_buf == NULL || write_buf == NULL) {
    return ESP_FAIL;
  }

  aenc_in_frame.buffer = read_buf;
  aenc_in_frame.len = read_size;
  aenc_out_frame.buffer = write_buf;
  aenc_out_frame.len = out_size;

  ESP_LOGI(TAG, "audio codec init done. in buffer size: %d, out buffer size: %d", read_size, out_size);
  return 0;
}

#if !defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
static esp_err_t pdm_audio_init(void) {
  i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
  ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, NULL, &rx_handle));

  i2s_pdm_rx_config_t pdm_rx_cfg = {
      .clk_cfg = I2S_PDM_RX_CLK_DEFAULT_CONFIG(8000),
      .slot_cfg = I2S_PDM_RX_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
      .gpio_cfg = {
          .clk = CONFIG_AUDIO_PDM_CLK_GPIO,
          .din = CONFIG_AUDIO_PDM_DATA_GPIO,
          .invert_flags = {
              .clk_inv = false,
          },
      },
  };

  ESP_ERROR_CHECK(i2s_channel_init_pdm_rx_mode(rx_handle, &pdm_rx_cfg));
  ESP_ERROR_CHECK(i2s_channel_enable(rx_handle));

  return audio_codec_init();
}

static void pdm_audio_deinit(void) {
  ESP_ERROR_CHECK(i2s_channel_disable(rx_handle));
  ESP_ERROR_CHECK(i2s_del_channel(rx_handle));
}

static int32_t pdm_audio_get_samples(uint8_t* buf, size_t size) {
  size_t bytes_read;

  if (i2s_channel_read(rx_handle, (char*)buf, size, &bytes_read, 1000) != ESP_OK) {
    ESP_LOGE(TAG, "i2s read error");
  }

  return bytes_read;
}
#endif

static esp_err_t msm261_audio_init(void) {
#if !defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  return ESP_ERR_NOT_SUPPORTED;
#else
  if (CONFIG_AUDIO_I2S_BCLK_GPIO < 0 || CONFIG_AUDIO_I2S_WS_GPIO < 0 || CONFIG_AUDIO_I2S_DATA_GPIO < 0) {
    ESP_LOGE(TAG, "invalid MSM261 I2S pin configuration");
    return ESP_ERR_INVALID_ARG;
  }

  i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
  ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, NULL, &rx_handle));

  esp_err_t err = msm261_enable_chip();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to enable MSM261");
    return err;
  }

  i2s_std_config_t std_cfg = {
      .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(8000),
      .slot_cfg = I2S_STD_MSB_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_MONO),
      .gpio_cfg = {
          .mclk = I2S_GPIO_UNUSED,
          .bclk = CONFIG_AUDIO_I2S_BCLK_GPIO,
          .ws = CONFIG_AUDIO_I2S_WS_GPIO,
          .dout = I2S_GPIO_UNUSED,
          .din = CONFIG_AUDIO_I2S_DATA_GPIO,
          .invert_flags = {
              .mclk_inv = false,
              .bclk_inv = false,
              .ws_inv = false,
          },
      },
  };
  std_cfg.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;

  ESP_ERROR_CHECK(i2s_channel_init_std_mode(rx_handle, &std_cfg));
  ESP_ERROR_CHECK(i2s_channel_enable(rx_handle));

  return audio_codec_init();
#endif
}

static void msm261_audio_deinit(void) {
  if (raw_i2s_buf) {
    free(raw_i2s_buf);
    raw_i2s_buf = NULL;
    raw_i2s_buf_size = 0;
  }

  ESP_ERROR_CHECK(i2s_channel_disable(rx_handle));
  ESP_ERROR_CHECK(i2s_del_channel(rx_handle));
  msm261_disable_chip();
}

static int32_t msm261_audio_get_samples(uint8_t* buf, size_t size) {
#if !defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  (void)buf;
  (void)size;
  return 0;
#else
  size_t bytes_read = 0;
  size_t samples_16bit = size / sizeof(int16_t);
  size_t bytes_needed = samples_16bit * sizeof(int32_t);

  if (raw_i2s_buf_size < bytes_needed) {
    uint8_t* resized = realloc(raw_i2s_buf, bytes_needed);
    if (!resized) {
      ESP_LOGE(TAG, "failed to allocate MSM261 sample buffer");
      return 0;
    }
    raw_i2s_buf = resized;
    raw_i2s_buf_size = bytes_needed;
  }

  if (i2s_channel_read(rx_handle, raw_i2s_buf, bytes_needed, &bytes_read, 1000) != ESP_OK) {
    ESP_LOGE(TAG, "i2s read error");
    return 0;
  }

  int32_t* src = (int32_t*)raw_i2s_buf;
  int16_t* dst = (int16_t*)buf;
  size_t samples_read = bytes_read / sizeof(int32_t);
  for (size_t i = 0; i < samples_read; i++) {
    dst[i] = (int16_t)(src[i] >> 14);
  }

  return (int32_t)(samples_read * sizeof(int16_t));
#endif
}

static esp_err_t msm261_enable_chip(void) {
#if !defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  return ESP_ERR_NOT_SUPPORTED;
#else
  if (CONFIG_AUDIO_I2S_CHIPEN_GPIO < 0) {
    return ESP_OK;
  }

  gpio_num_t chipen_gpio = (gpio_num_t)CONFIG_AUDIO_I2S_CHIPEN_GPIO;
  gpio_config_t io_conf = {
      .pin_bit_mask = 0,
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  io_conf.pin_bit_mask = BIT64(chipen_gpio);
  esp_err_t err = gpio_config(&io_conf);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to configure CHIPEN GPIO");
    return err;
  }

  return gpio_set_level(chipen_gpio, 1);
#endif
}

static void msm261_disable_chip(void) {
#if defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  if (CONFIG_AUDIO_I2S_CHIPEN_GPIO >= 0) {
    gpio_set_level(CONFIG_AUDIO_I2S_CHIPEN_GPIO, 0);
  }
#endif
}

static esp_err_t audio_input_init(void) {
#if defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  return msm261_audio_init();
#else
  return pdm_audio_init();
#endif
}

static void audio_input_deinit(void) {
#if defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  msm261_audio_deinit();
#else
  pdm_audio_deinit();
#endif
}

static int32_t audio_input_get_samples(uint8_t* buf, size_t size) {
#if defined(CONFIG_AUDIO_INPUT_I2S_MSM261)
  return msm261_audio_get_samples(buf, size);
#else
  return pdm_audio_get_samples(buf, size);
#endif
}

esp_err_t audio_init(void) {
  return audio_input_init();
}

void audio_deinit(void) {
  audio_input_deinit();
}

int32_t audio_get_samples(uint8_t* buf, size_t size) {
  return audio_input_get_samples(buf, size);
}

esp_err_t audio_set_gain(int gain) {
  if (gain < 1 || gain > 64) {
    return ESP_ERR_INVALID_ARG;
  }

  s_audio_input_gain = gain;
  ESP_LOGI(TAG, "audio input gain set to %d", gain);
  return ESP_OK;
}

int audio_get_gain(void) {
  return s_audio_input_gain;
}

void audio_task(void* arg) {
  int ret;
  static int64_t last_time;
  static int64_t last_level_log_time;
  int64_t curr_time;
  float bytes = 0;

  last_time = get_timestamp();
  last_level_log_time = last_time - 1000;
  ESP_LOGI(TAG, "audio task started");

  for (;;) {
    if (eState == PEER_CONNECTION_COMPLETED) {
      if (g_audio_send_enable_time > 0 && get_timestamp() < g_audio_send_enable_time) {
        vTaskDelay(pdMS_TO_TICKS(20));
        continue;
      }

      ret = audio_get_samples(aenc_in_frame.buffer, aenc_in_frame.len);

      if (ret == aenc_in_frame.len) {
        int16_t* samples = (int16_t*)aenc_in_frame.buffer;
        size_t sample_count = ret / sizeof(int16_t);
        int peak = 0;

        audio_apply_gain(samples, sample_count);
        for (size_t i = 0; i < sample_count; i++) {
          int sample = samples[i];
          if (sample < 0) {
            sample = -sample;
          }
          if (sample > peak) {
            peak = sample;
          }
        }

        if (esp_audio_enc_process(enc_handle, &aenc_in_frame, &aenc_out_frame) == ESP_AUDIO_ERR_OK) {
          peer_connection_send_audio(g_pc, aenc_out_frame.buffer, aenc_out_frame.encoded_bytes);

          bytes += aenc_out_frame.encoded_bytes;
          curr_time = get_timestamp();
          if (curr_time - last_level_log_time >= 5000) {
            ESP_LOGI(TAG, "audio level peak=%d encoded_bytes=%d stack_hw=%u",
                     peak,
                     aenc_out_frame.encoded_bytes,
                     (unsigned)uxTaskGetStackHighWaterMark(NULL));
            last_level_log_time = curr_time;
          }
          if (bytes > 50000) {
            ESP_LOGI(TAG, "audio bitrate: %.1f bps", 1000.0 * (bytes * 8.0 / (float)(curr_time - last_time)));
            last_time = curr_time;
            bytes = 0;
          }
        }
      }
      vTaskDelay(pdMS_TO_TICKS(5));

    } else {
      vTaskDelay(pdMS_TO_TICKS(100));
    }
  }
}
