#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "agent.h"
#include "config.h"
#include "dtls_srtp.h"
#include "peer_connection.h"
#include "ports.h"
#include "rtcp.h"
#include "rtp.h"
#include "sctp.h"
#include "sdp.h"

#define STATE_CHANGED(pc, curr_state)                                 \
  if (pc->oniceconnectionstatechange && pc->state != curr_state) {    \
    pc->oniceconnectionstatechange(curr_state, pc->config.user_data); \
    pc->state = curr_state;                                           \
  }

struct PeerConnection {
  PeerConfiguration config;
  PeerConnectionState state;
  Agent agent;
  DtlsSrtp dtls_srtp;
  Sctp sctp;

  char sdp[CONFIG_SDP_BUFFER_SIZE];

  void (*onicecandidate)(char* sdp, void* user_data);
  void (*oniceconnectionstatechange)(PeerConnectionState state, void* user_data);
  void (*on_connected)(void* userdata);
  void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* user_data);

  uint8_t temp_buf[CONFIG_MTU];
  uint8_t agent_buf[CONFIG_MTU];
  int agent_ret;
  int b_local_description_created;
  int64_t checking_started_ms;
  int64_t checking_total_started_ms;
  SemaphoreHandle_t io_lock;

  RtpEncoder artp_encoder;
  RtpEncoder vrtp_encoder;
  RtpDecoder vrtp_decoder;
  RtpDecoder artp_decoder;

  uint32_t remote_assrc;
  uint32_t remote_vssrc;
};

static void peer_connection_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
  PeerConnection* pc = (PeerConnection*)user_data;
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  agent_send(&pc->agent, data, size);
}

static void peer_connection_log_dtls_record(const char* prefix, const unsigned char* buf, size_t len) {
  uint16_t version = 0;
  uint16_t epoch = 0;
  uint64_t sequence = 0;
  uint16_t payload_len = 0;

  if (buf == NULL || len < 13) {
    return;
  }

  version = ((uint16_t)buf[1] << 8) | buf[2];
  epoch = ((uint16_t)buf[3] << 8) | buf[4];
  sequence = ((uint64_t)buf[5] << 40) |
             ((uint64_t)buf[6] << 32) |
             ((uint64_t)buf[7] << 24) |
             ((uint64_t)buf[8] << 16) |
             ((uint64_t)buf[9] << 8) |
             (uint64_t)buf[10];
  payload_len = ((uint16_t)buf[11] << 8) | buf[12];

  LOGI("%s type=0x%02x ver=0x%04x epoch=%u seq=%llu rec_len=%u",
       prefix,
       buf[0],
       version,
       epoch,
       (unsigned long long)sequence,
       payload_len);
}

static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int recv_max = 0;
  int ret = MBEDTLS_ERR_SSL_WANT_READ;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  IceCandidatePair* pair = pc->agent.selected_pair ? pc->agent.selected_pair : pc->agent.nominated_pair;
  int allow_turn_source = 0;

  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  if (pair != NULL && pair->local != NULL && pair->remote != NULL) {
    if (pair->local->type == ICE_CANDIDATE_TYPE_RELAY || pair->remote->type == ICE_CANDIDATE_TYPE_RELAY) {
      allow_turn_source = 1;
    }
  }

  while (recv_max < CONFIG_TLS_READ_TIMEOUT && pc->state == PEER_CONNECTION_CONNECTED) {
    ret = agent_recv(&pc->agent, buf, len);

    if (ret > 0) {
      char recv_addr[ADDRSTRLEN];
      addr_to_string(&pc->agent.last_recv_addr, recv_addr, sizeof(recv_addr));
      if (pair != NULL && pair->remote != NULL && !addr_equal(&pc->agent.last_recv_addr, &pair->remote->addr)) {
        if (!(allow_turn_source && addr_equal(&pc->agent.last_recv_addr, &pc->agent.turn.server_addr))) {
        char expected_addr[ADDRSTRLEN];
        addr_to_string(&pair->remote->addr, expected_addr, sizeof(expected_addr));
        LOGI("DTLS ignore packet from=%s:%d expected=%s:%d",
             recv_addr,
             pc->agent.last_recv_addr.port,
             expected_addr,
             pair->remote->addr.port);
        ret = MBEDTLS_ERR_SSL_WANT_READ;
        continue;
        }
      }
      LOGI("DTLS recv packet len=%d first_byte=0x%02x from=%s:%d", ret, buf[0], recv_addr, pc->agent.last_recv_addr.port);
      peer_connection_log_dtls_record("DTLS recv record", buf, (size_t)ret);
      break;
    }

    recv_max++;
  }
  if (ret <= 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return ret;
}

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  IceCandidatePair* pair = pc->agent.selected_pair ? pc->agent.selected_pair : pc->agent.nominated_pair;
  char remote_addr[ADDRSTRLEN];
  int ret;

  if (pair != NULL && pair->remote != NULL) {
    addr_to_string(&pair->remote->addr, remote_addr, sizeof(remote_addr));
    LOGI("DTLS send packet len=%d first_byte=0x%02x to=%s:%d",
         (int)len,
         len > 0 ? buf[0] : 0,
         remote_addr,
         pair->remote->addr.port);
    peer_connection_log_dtls_record("DTLS send record", buf, len);
  } else {
    LOGI("DTLS send packet len=%d first_byte=0x%02x to=<none>", (int)len, len > 0 ? buf[0] : 0);
    peer_connection_log_dtls_record("DTLS send record", buf, len);
  }
  ret = agent_send(&pc->agent, buf, len);
  if (ret < 0) {
    return ret;
  }
  return (int)len;
}

static void peer_connection_incoming_rtcp(PeerConnection* pc, uint8_t* buf, size_t len) {
  RtcpHeader* rtcp_header;
  size_t pos = 0;

  while (pos < len) {
    rtcp_header = (RtcpHeader*)(buf + pos);

    switch (rtcp_header->type) {
      case RTCP_RR:
        LOGD("RTCP_PR");
        if (rtcp_header->rc > 0) {
// TODO: REMB, GCC ...etc
#if 0
          RtcpRr rtcp_rr = rtcp_parse_rr(buf);
          uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
          uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
          if(pc->on_receiver_packet_loss && fraction > 0) {

            pc->on_receiver_packet_loss((float)fraction/256.0, total, pc->config.user_data);
          }
#endif
        }
        break;
      case RTCP_PSFB: {
        int fmt = rtcp_header->rc;
        LOGD("RTCP_PSFB %d", fmt);
        // PLI and FIR
        if ((fmt == 1 || fmt == 4) && pc->config.on_request_keyframe) {
          pc->config.on_request_keyframe(pc->config.user_data);
        }
      }
      default:
        break;
    }

    pos += 4 * ntohs(rtcp_header->length) + 4;
  }
}

static void peer_connection_log_timed_out_pair(PeerConnection* pc) {
  char local_addr[ADDRSTRLEN];
  char remote_addr[ADDRSTRLEN];
  IceCandidatePair* pair = pc->agent.nominated_pair;

  if (pair == NULL || pair->local == NULL || pair->remote == NULL) {
    LOGI("ICE trial timeout for current candidate pair");
    return;
  }

  addr_to_string(&pair->local->addr, local_addr, sizeof(local_addr));
  addr_to_string(&pair->remote->addr, remote_addr, sizeof(remote_addr));
  LOGI("ICE trial timeout pair local=%s:%d remote=%s:%d conncheck=%d priority=%" PRIu32,
       local_addr,
       pair->local->addr.port,
       remote_addr,
       pair->remote->addr.port,
       pair->conncheck,
       (uint32_t)pair->priority);
}

static int peer_connection_trial_timeout_ms(PeerConnection* pc) {
  IceCandidatePair* pair = pc->agent.nominated_pair;

  if (pair != NULL && pair->local != NULL && pair->remote != NULL) {
    if (pair->local->type == ICE_CANDIDATE_TYPE_RELAY ||
        pair->remote->type == ICE_CANDIDATE_TYPE_RELAY) {
      return CONFIG_ICE_TRIAL_TIMEOUT_TURN;
    }
  }

  return CONFIG_ICE_TRIAL_TIMEOUT;
}

const char* peer_connection_state_to_string(PeerConnectionState state) {
  switch (state) {
    case PEER_CONNECTION_NEW:
      return "new";
    case PEER_CONNECTION_CHECKING:
      return "checking";
    case PEER_CONNECTION_CONNECTED:
      return "connected";
    case PEER_CONNECTION_COMPLETED:
      return "completed";
    case PEER_CONNECTION_FAILED:
      return "failed";
    case PEER_CONNECTION_CLOSED:
      return "closed";
    case PEER_CONNECTION_DISCONNECTED:
      return "disconnected";
    default:
      return "unknown";
  }
}

PeerConnectionState peer_connection_get_state(PeerConnection* pc) {
  return pc->state;
}

int peer_connection_get_local_candidate_count(PeerConnection* pc) {
  return pc ? pc->agent.local_candidates_count : 0;
}

int peer_connection_get_remote_candidate_count(PeerConnection* pc) {
  return pc ? pc->agent.remote_candidates_count : 0;
}

void* peer_connection_get_sctp(PeerConnection* pc) {
  return &pc->sctp;
}

PeerConnection* peer_connection_create(PeerConfiguration* config) {
  PeerConnection* pc = calloc(1, sizeof(PeerConnection));
  if (!pc) {
    return NULL;
  }

  memcpy(&pc->config, config, sizeof(PeerConfiguration));

  agent_create(&pc->agent);
  pc->io_lock = xSemaphoreCreateMutex();
  pc->checking_started_ms = 0;
  pc->checking_total_started_ms = 0;

  memset(&pc->sctp, 0, sizeof(pc->sctp));

  if (pc->config.audio_codec) {
    rtp_encoder_init(&pc->artp_encoder, pc->config.audio_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->artp_decoder, pc->config.audio_codec,
                     pc->config.onaudiotrack, pc->config.user_data);
  }

  if (pc->config.video_codec) {
    rtp_encoder_init(&pc->vrtp_encoder, pc->config.video_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->vrtp_decoder, pc->config.video_codec,
                     pc->config.onvideotrack, pc->config.user_data);
  }

  return pc;
}

void peer_connection_destroy(PeerConnection* pc) {
  if (pc) {
    if (pc->io_lock != NULL) {
      vSemaphoreDelete(pc->io_lock);
      pc->io_lock = NULL;
    }
    sctp_destroy_association(&pc->sctp);
    dtls_srtp_deinit(&pc->dtls_srtp);
    agent_destroy(&pc->agent);
    free(pc);
    pc = NULL;
  }
}

void peer_connection_close(PeerConnection* pc) {
  pc->state = PEER_CONNECTION_CLOSED;
}

int peer_connection_send_audio(PeerConnection* pc, const uint8_t* buf, size_t len) {
  int ret = -1;

  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
  if (pc->io_lock != NULL) {
    if (xSemaphoreTake(pc->io_lock, portMAX_DELAY) != pdTRUE) {
      return -1;
    }
  }
  ret = rtp_encoder_encode(&pc->artp_encoder, buf, len);
  if (pc->io_lock != NULL) {
    xSemaphoreGive(pc->io_lock);
  }
  return ret;
}

int peer_connection_send_video(PeerConnection* pc, const uint8_t* buf, size_t len) {
  int ret = -1;

  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
  if (pc->io_lock != NULL) {
    if (xSemaphoreTake(pc->io_lock, portMAX_DELAY) != pdTRUE) {
      return -1;
    }
  }
  ret = rtp_encoder_encode(&pc->vrtp_encoder, buf, len);
  if (pc->io_lock != NULL) {
    xSemaphoreGive(pc->io_lock);
  }
  return ret;
}

int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len) {
  return peer_connection_datachannel_send_sid(pc, message, len, 0);
}

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  int ret = -1;

  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return -1;
  }
  if (pc->io_lock != NULL) {
    if (xSemaphoreTake(pc->io_lock, portMAX_DELAY) != pdTRUE) {
      return -1;
    }
  }
  if (pc->config.datachannel == DATA_CHANNEL_STRING) {
    ret = sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  } else {
    ret = sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
  }
  if (pc->io_lock != NULL) {
    xSemaphoreGive(pc->io_lock);
  }
  return ret;
}

int peer_connection_create_datachannel(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol) {
  return peer_connection_create_datachannel_sid(pc, channel_type, priority, reliability_parameter, label, protocol, 0);
}

int peer_connection_create_datachannel_sid(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol, uint16_t sid) {
  int rtrn = -1;

  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return rtrn;
  }

  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Message Type |  Channel Type |            Priority           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                    Reliability Parameter                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Label Length          |       Protocol Length         |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                             Label                             |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                            Protocol                           |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  int msg_size = 12 + strlen(label) + strlen(protocol);
  uint16_t priority_big_endian = htons(priority);
  uint32_t reliability_big_endian = ntohl(reliability_parameter);
  uint16_t label_length = htons(strlen(label));
  uint16_t protocol_length = htons(strlen(protocol));
  char* msg = calloc(1, msg_size);
  if (!msg) {
    return rtrn;
  }

  msg[0] = DATA_CHANNEL_OPEN;
  memcpy(msg + 2, &priority_big_endian, sizeof(uint16_t));
  memcpy(msg + 4, &reliability_big_endian, sizeof(uint32_t));
  memcpy(msg + 8, &label_length, sizeof(uint16_t));
  memcpy(msg + 10, &protocol_length, sizeof(uint16_t));
  memcpy(msg + 12, label, strlen(label));
  memcpy(msg + 12 + strlen(label), protocol, strlen(protocol));

  rtrn = sctp_outgoing_data(&pc->sctp, msg, msg_size, PPID_CONTROL, sid);
  free(msg);
  return rtrn;
}

static char* peer_connection_dtls_role_setup_value(DtlsSrtpRole d) {
  return d == DTLS_SRTP_ROLE_SERVER ? "a=setup:passive" : "a=setup:active";
}

int peer_connection_loop(PeerConnection* pc) {
  int ret = -1;
  uint32_t ssrc = 0;
  int64_t now = 0;
  IceCandidatePair* previous_pair = NULL;

  if (pc->io_lock != NULL) {
    if (xSemaphoreTake(pc->io_lock, portMAX_DELAY) != pdTRUE) {
      return -1;
    }
  }

  memset(pc->agent_buf, 0, sizeof(pc->agent_buf));
  pc->agent_ret = -1;
  if (agent_maintain_turn(&pc->agent) != 0) {
    LOGW("TURN maintenance error");
  }

  switch (pc->state) {
    case PEER_CONNECTION_NEW:
      break;

    case PEER_CONNECTION_CHECKING:
      now = ports_get_epoch_time();
      int trial_timeout_ms = peer_connection_trial_timeout_ms(pc);
      if (pc->checking_started_ms == 0) {
        pc->checking_started_ms = now;
      }
      if (pc->checking_total_started_ms == 0) {
        pc->checking_total_started_ms = now;
      }
      if (CONFIG_ICE_TOTAL_TIMEOUT > 0 &&
          (now - pc->checking_total_started_ms) > CONFIG_ICE_TOTAL_TIMEOUT) {
        LOGI("ICE total timeout after %lldms", (long long)(now - pc->checking_total_started_ms));
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
        break;
      }
      if (pc->agent.nominated_pair != NULL &&
          trial_timeout_ms > 0 &&
          (now - pc->checking_started_ms) > trial_timeout_ms) {
        peer_connection_log_timed_out_pair(pc);
        if (pc->agent.nominated_pair != NULL) {
          pc->agent.nominated_pair->state = ICE_CANDIDATE_STATE_FAILED;
          pc->agent.nominated_pair = NULL;
        }
        pc->checking_started_ms = now;
      }
      if (pc->agent.candidate_pairs_num == 0) {
        LOGD("waiting for remote ICE candidates");
      } else {
        previous_pair = pc->agent.nominated_pair;
        if (agent_select_candidate_pair(&pc->agent) < 0) {
          pc->checking_started_ms = 0;
          LOGD("all current candidate pairs are exhausted, waiting for late candidates");
        } else {
          if (pc->agent.nominated_pair != NULL && pc->agent.nominated_pair != previous_pair) {
            pc->checking_started_ms = now;
          }
          if (agent_connectivity_check(&pc->agent) == 0) {
            STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
          }
        }
      }
      break;

    case PEER_CONNECTION_CONNECTED:
      if (pc->agent.selected_pair != NULL && pc->agent.selected_pair->local != NULL && pc->agent.selected_pair->remote != NULL) {
        char local_addr[ADDRSTRLEN];
        char remote_addr[ADDRSTRLEN];
        addr_to_string(&pc->agent.selected_pair->local->addr, local_addr, sizeof(local_addr));
        addr_to_string(&pc->agent.selected_pair->remote->addr, remote_addr, sizeof(remote_addr));
        LOGI("DTLS using selected pair local=%s:%d remote=%s:%d local_type=%d remote_type=%d",
             local_addr,
             pc->agent.selected_pair->local->addr.port,
             remote_addr,
             pc->agent.selected_pair->remote->addr.port,
             pc->agent.selected_pair->local->type,
             pc->agent.selected_pair->remote->type);
      }

      if (dtls_srtp_handshake(&pc->dtls_srtp,
                              pc->agent.selected_pair != NULL ? &pc->agent.selected_pair->remote->addr : NULL) == 0) {
        LOGD("DTLS-SRTP handshake done");

        if (pc->config.datachannel) {
          LOGI("SCTP create socket");
          sctp_create_association(&pc->sctp, &pc->dtls_srtp);
          pc->sctp.userdata = pc->config.user_data;
        }

        STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
      }
      break;
    case PEER_CONNECTION_COMPLETED:
      if ((pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf))) > 0) {
        LOGD("agent_recv %d", pc->agent_ret);

        if (rtcp_probe(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTCP packet");
          dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);
          peer_connection_incoming_rtcp(pc, pc->agent_buf, pc->agent_ret);

        } else if (dtls_srtp_probe(pc->agent_buf)) {
          int ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
          LOGD("Got DTLS data %d", ret);

          if (ret > 0) {
            sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
          }

        } else if (rtp_packet_validate(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTP packet");

          dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);

          ssrc = rtp_get_ssrc(pc->agent_buf);
          if (ssrc == pc->remote_assrc) {
            rtp_decoder_decode(&pc->artp_decoder, pc->agent_buf, pc->agent_ret);
          } else if (ssrc == pc->remote_vssrc) {
            rtp_decoder_decode(&pc->vrtp_decoder, pc->agent_buf, pc->agent_ret);
          }

        } else {
          LOGW("Unknown data");
        }
      }

      if (CONFIG_KEEPALIVE_TIMEOUT > 0 && (ports_get_epoch_time() - pc->agent.last_activity_time) > CONFIG_KEEPALIVE_TIMEOUT) {
        LOGI("peer activity timeout");
        STATE_CHANGED(pc, PEER_CONNECTION_CLOSED);
      }

      break;
    case PEER_CONNECTION_FAILED:
      pc->checking_started_ms = 0;
      break;
    case PEER_CONNECTION_DISCONNECTED:
      break;
    case PEER_CONNECTION_CLOSED:
      pc->checking_started_ms = 0;
      pc->checking_total_started_ms = 0;
      break;
    default:
      break;
  }

  ret = 0;
  if (pc->io_lock != NULL) {
    xSemaphoreGive(pc->io_lock);
  }
  return ret;
}

void peer_connection_set_remote_description(PeerConnection* pc, const char* sdp, SdpType type) {
  char* start = (char*)sdp;
  char* line = NULL;
  char buf[256];
  char* val_start = NULL;
  uint32_t* ssrc = NULL;
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;
  int is_update = 0;
  Agent* agent = &pc->agent;

  while ((line = strstr(start, "\r\n"))) {
    size_t line_len = (size_t)(line - start);

    memset(buf, 0, sizeof(buf));
    if (line_len >= sizeof(buf)) {
      line_len = sizeof(buf) - 1;
    }
    memcpy(buf, start, line_len);
    buf[line_len] = '\0';

    if (strstr(buf, "a=setup:passive")) {
      role = DTLS_SRTP_ROLE_CLIENT;
    }

    if (strstr(buf, "a=fingerprint")) {
      strncpy(pc->dtls_srtp.remote_fingerprint, buf + 22, sizeof(pc->dtls_srtp.remote_fingerprint) - 1);
    }

    if (strstr(buf, "a=ice-ufrag") &&
        strlen(agent->remote_ufrag) != 0 &&
        (strncmp(buf + strlen("a=ice-ufrag:"), agent->remote_ufrag, strlen(agent->remote_ufrag)) == 0)) {
      is_update = 1;
    }

    if (strstr(buf, "m=video")) {
      ssrc = &pc->remote_vssrc;
    } else if (strstr(buf, "m=audio")) {
      ssrc = &pc->remote_assrc;
    }

    if ((val_start = strstr(buf, "a=ssrc:")) && ssrc) {
      *ssrc = strtoul(val_start + 7, NULL, 10);
      LOGD("SSRC: %" PRIu32, *ssrc);
    }

    start = line + 2;
  }

  if (is_update) {
    LOGI("remote description update ignored because ICE ufrag matched an existing session");
    return;
  }

  agent_set_remote_description(&pc->agent, (char*)sdp);
  LOGI("remote description applied: remote_candidates=%d", agent->remote_candidates_count);
  if (type == SDP_TYPE_ANSWER) {
    agent_update_candidate_pairs(&pc->agent);
    pc->checking_started_ms = ports_get_epoch_time();
    pc->checking_total_started_ms = pc->checking_started_ms;
    STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  }
}

static const char* peer_connection_create_sdp(PeerConnection* pc, SdpType sdp_type) {
  char* description = (char*)pc->temp_buf;
  int appended_candidates = 0;

  memset(pc->temp_buf, 0, sizeof(pc->temp_buf));
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;

  pc->sctp.connected = 0;

  switch (sdp_type) {
    case SDP_TYPE_OFFER:
      role = DTLS_SRTP_ROLE_SERVER;
      agent_clear_candidates(&pc->agent);
      pc->agent.mode = AGENT_MODE_CONTROLLING;
      break;
    case SDP_TYPE_ANSWER:
      role = DTLS_SRTP_ROLE_CLIENT;
      pc->agent.mode = AGENT_MODE_CONTROLLED;
      break;
    default:
      break;
  }

  dtls_srtp_reset_session(&pc->dtls_srtp);
  dtls_srtp_init(&pc->dtls_srtp, role, pc);
  pc->dtls_srtp.udp_recv = peer_connection_dtls_srtp_recv;
  pc->dtls_srtp.udp_send = peer_connection_dtls_srtp_send;

  memset(pc->sdp, 0, sizeof(pc->sdp));
  // TODO: check if we have video or audio codecs
  sdp_create(pc->sdp,
             pc->config.video_codec != CODEC_NONE,
             pc->config.audio_codec != CODEC_NONE,
             pc->config.datachannel);

  agent_create_ice_credential(&pc->agent);
  sdp_append(pc->sdp, "a=ice-ufrag:%s", pc->agent.local_ufrag);
  sdp_append(pc->sdp, "a=ice-pwd:%s", pc->agent.local_upwd);
  sdp_append(pc->sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
  sdp_append(pc->sdp, peer_connection_dtls_role_setup_value(role));

  pc->b_local_description_created = 1;

  agent_gather_candidate(&pc->agent, NULL, NULL, NULL);  // host address
  for (int i = 0; i < sizeof(pc->config.ice_servers) / sizeof(pc->config.ice_servers[0]); ++i) {
    if (pc->config.ice_servers[i].urls) {
      LOGI("ice server: %s", pc->config.ice_servers[i].urls);
      agent_gather_candidate(&pc->agent, pc->config.ice_servers[i].urls, pc->config.ice_servers[i].username, pc->config.ice_servers[i].credential);
    }
  }

  memset(description, 0, sizeof(pc->temp_buf));
  agent_get_local_description(&pc->agent, description, sizeof(pc->temp_buf));

  if (pc->config.video_codec == CODEC_H264) {
    sdp_append_h264(pc->sdp);
    if (!appended_candidates) {
      sdp_append(pc->sdp, description);
      appended_candidates = 1;
    }
  }

  switch (pc->config.audio_codec) {
    case CODEC_PCMA:
      sdp_append_pcma(pc->sdp);
      if (!appended_candidates) {
        sdp_append(pc->sdp, description);
        appended_candidates = 1;
      }
      break;
    case CODEC_PCMU:
      sdp_append_pcmu(pc->sdp);
      if (!appended_candidates) {
        sdp_append(pc->sdp, description);
        appended_candidates = 1;
      }
      break;
    case CODEC_OPUS:
      sdp_append_opus(pc->sdp);
      if (!appended_candidates) {
        sdp_append(pc->sdp, description);
        appended_candidates = 1;
      }
    default:
      break;
  }

  if (pc->config.datachannel) {
    sdp_append_datachannel(pc->sdp);
    if (!appended_candidates) {
      sdp_append(pc->sdp, description);
      appended_candidates = 1;
    }
  }

  if (!appended_candidates) {
    sdp_append(pc->sdp, description);
  }

  if (pc->onicecandidate) {
    pc->onicecandidate(pc->sdp, pc->config.user_data);
  }

  LOGI("created %s SDP: local_candidates=%d remote_candidates=%d",
       sdp_type == SDP_TYPE_OFFER ? "offer" : "answer",
       pc->agent.local_candidates_count,
       pc->agent.remote_candidates_count);

  return pc->sdp;
}

const char* peer_connection_create_offer(PeerConnection* pc) {
  return peer_connection_create_sdp(pc, SDP_TYPE_OFFER);
}

const char* peer_connection_create_answer(PeerConnection* pc) {
  const char* sdp = peer_connection_create_sdp(pc, SDP_TYPE_ANSWER);
  agent_update_candidate_pairs(&pc->agent);
  STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  return sdp;
}

int peer_connection_send_rtcp_pil(PeerConnection* pc, uint32_t ssrc) {
  int ret = -1;
  uint8_t plibuf[128];
  rtcp_get_pli(plibuf, 12, ssrc);

  // TODO: encrypt rtcp packet
  // guint size = 12;
  // dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  // ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  return ret;
}

// callbacks
void peer_connection_on_connected(PeerConnection* pc, void (*on_connected)(void* userdata)) {
  pc->on_connected = on_connected;
}

void peer_connection_on_receiver_packet_loss(PeerConnection* pc,
                                             void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* userdata)) {
  pc->on_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_onicecandidate(PeerConnection* pc, void (*onicecandidate)(char* sdp, void* userdata)) {
  pc->onicecandidate = onicecandidate;
}

void peer_connection_oniceconnectionstatechange(PeerConnection* pc,
                                                void (*oniceconnectionstatechange)(PeerConnectionState state, void* userdata)) {
  pc->oniceconnectionstatechange = oniceconnectionstatechange;
}

void peer_connection_ondatachannel(PeerConnection* pc,
                                   void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid),
                                   void (*onopen)(void* userdata),
                                   void (*onclose)(void* userdata)) {
  if (pc) {
    sctp_onopen(&pc->sctp, onopen);
    sctp_onclose(&pc->sctp, onclose);
    sctp_onmessage(&pc->sctp, onmessage);
  }
}

int peer_connection_lookup_sid(PeerConnection* pc, const char* label, uint16_t* sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (strncmp(pc->sctp.stream_table[i].label, label, sizeof(pc->sctp.stream_table[i].label)) == 0) {
      *sid = pc->sctp.stream_table[i].sid;
      return 0;
    }
  }
  return -1;  // Not found
}

char* peer_connection_lookup_sid_label(PeerConnection* pc, uint16_t sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (pc->sctp.stream_table[i].sid == sid) {
      return pc->sctp.stream_table[i].label;
    }
  }
  return NULL;  // Not found
}

int peer_connection_add_ice_candidate(PeerConnection* pc, char* candidate) {
  Agent* agent = &pc->agent;

  if (candidate != NULL && strstr(candidate, ".local") != NULL) {
    LOGW("ignore unresolved mDNS ICE candidate: %s", candidate);
    return 0;
  }

  if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
    LOGE("remote candidate table is full");
    return -1;
  }
  if (ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count], candidate, candidate + strlen(candidate)) != 0) {
    LOGE("failed to parse remote ICE candidate: %s", candidate);
    return -1;
  }
  LOGD("Add candidate: %s", candidate);
  agent->remote_candidates_count++;
  LOGI("remote candidate added, total=%d", agent->remote_candidates_count);
  agent_prepare_turn_peer(agent, &agent->remote_candidates[agent->remote_candidates_count - 1].addr);
  if (agent->local_candidates_count > 0) {
    agent_update_candidate_pairs(agent);
    if (pc->state == PEER_CONNECTION_CHECKING || pc->state == PEER_CONNECTION_FAILED) {
      pc->checking_started_ms = ports_get_epoch_time();
    }
    if (pc->state == PEER_CONNECTION_FAILED) {
      pc->state = PEER_CONNECTION_CHECKING;
      if (pc->checking_total_started_ms == 0) {
        pc->checking_total_started_ms = pc->checking_started_ms;
      }
      LOGI("restart ICE checking after late candidate arrival");
    }
  }
  return 0;
}
