#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "agent.h"
#include "base64.h"
#include "ice.h"
#include "ports.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

#define AGENT_POLL_TIMEOUT 1
#define AGENT_CONNCHECK_MAX 1000
#define AGENT_CONNCHECK_PERIOD 100
#define AGENT_STUN_RECV_MAXTIMES 1000

static uint64_t agent_htonll(uint64_t value) {
  uint32_t high = htonl((uint32_t)(value >> 32));
  uint32_t low = htonl((uint32_t)(value & 0xFFFFFFFFu));
  return ((uint64_t)low << 32) | high;
}

static int agent_turn_tcp_recv_message(Agent* agent, uint8_t* buf, int len);
static int agent_turn_stream_recv(Agent* agent, uint8_t* buf, int len);
static int agent_turn_stream_send(Agent* agent, const uint8_t* buf, int len);
static void agent_turn_disable_transport(Agent* agent, const char* reason);

static void agent_log_candidate_pair(const char* prefix, const IceCandidatePair* pair) {
  char local_addr[ADDRSTRLEN];
  char remote_addr[ADDRSTRLEN];

  if (pair == NULL || pair->local == NULL || pair->remote == NULL) {
    return;
  }

  addr_to_string(&pair->local->addr, local_addr, sizeof(local_addr));
  addr_to_string(&pair->remote->addr, remote_addr, sizeof(remote_addr));
  LOGI("%s local=%s:%d(%d) remote=%s:%d(%d) priority=%" PRIu32 " conncheck=%d",
       prefix,
       local_addr,
       pair->local->addr.port,
       pair->local->type,
       remote_addr,
       pair->remote->addr.port,
       pair->remote->type,
       (uint32_t)pair->priority,
       pair->conncheck);
}

static int agent_candidate_pair_matches(const IceCandidatePair* pair,
                                        const IceCandidate* local,
                                        const IceCandidate* remote) {
  if (pair == NULL || pair->local == NULL || pair->remote == NULL || local == NULL || remote == NULL) {
    return 0;
  }
  return addr_equal(&pair->local->addr, &local->addr) && addr_equal(&pair->remote->addr, &remote->addr);
}

static IceCandidatePair* agent_active_pair(Agent* agent) {
  if (agent->selected_pair != NULL) {
    return agent->selected_pair;
  }
  return agent->nominated_pair;
}

static int agent_is_relay_relay_pair(const IceCandidatePair* pair) {
  return pair != NULL &&
         pair->local != NULL &&
         pair->remote != NULL &&
         pair->local->type == ICE_CANDIDATE_TYPE_RELAY &&
         pair->remote->type == ICE_CANDIDATE_TYPE_RELAY;
}

void agent_clear_candidates(Agent* agent) {
  agent->local_candidates_count = 0;
  agent->remote_candidates_count = 0;
  agent->candidate_pairs_num = 0;
}

int agent_create(Agent* agent) {
  int ret;
  memset(agent, 0, sizeof(*agent));
  if ((ret = udp_socket_open(&agent->udp_sockets[0], AF_INET, 0)) < 0) {
    LOGE("Failed to create UDP socket.");
    return ret;
  }
  LOGI("create IPv4 UDP socket: %d", agent->udp_sockets[0].fd);

#if CONFIG_IPV6
  if ((ret = udp_socket_open(&agent->udp_sockets[1], AF_INET6, 0)) < 0) {
    LOGE("Failed to create IPv6 UDP socket.");
    return ret;
  }
  LOGI("create IPv6 UDP socket: %d", agent->udp_sockets[1].fd);
#endif

  agent_clear_candidates(agent);
  turn_client_init(&agent->turn);
  agent->turn_tcp_socket.fd = -1;
  agent->turn_use_tcp = 0;
  agent->turn_use_tls = 0;
  memset(&agent->turn_tls_ctx, 0, sizeof(agent->turn_tls_ctx));
  memset(agent->turn_host, 0, sizeof(agent->turn_host));
  memset(agent->remote_ufrag, 0, sizeof(agent->remote_ufrag));
  memset(agent->remote_upwd, 0, sizeof(agent->remote_upwd));
  return 0;
}

void agent_destroy(Agent* agent) {
  if (agent->turn_use_tls) {
    ssl_transport_disconnect(&agent->turn_tls_ctx);
  }
  if (agent->turn_tcp_socket.fd > 0) {
    tcp_socket_close(&agent->turn_tcp_socket);
  }
  if (agent->udp_sockets[0].fd > 0) {
    udp_socket_close(&agent->udp_sockets[0]);
  }

#if CONFIG_IPV6
  if (agent->udp_sockets[1].fd > 0) {
    udp_socket_close(&agent->udp_sockets[1]);
  }
#endif
}

static int agent_socket_recv(Agent* agent, Address* addr, uint8_t* buf, int len) {
  int ret = -1;
  int i = 0;
  int maxfd = -1;
  int tcp_ready = 0;
  fd_set rfds;
  struct timeval tv;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  tv.tv_sec = 0;
  tv.tv_usec = AGENT_POLL_TIMEOUT * 1000;
  FD_ZERO(&rfds);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (agent->udp_sockets[i].fd > maxfd) {
      maxfd = agent->udp_sockets[i].fd;
    }
    if (agent->udp_sockets[i].fd >= 0) {
      FD_SET(agent->udp_sockets[i].fd, &rfds);
    }
  }
  if ((agent->turn_use_tcp || agent->turn_use_tls) &&
      (agent->turn_use_tls ? agent->turn_tls_ctx.tcp_socket.fd : agent->turn_tcp_socket.fd) >= 0) {
    int turn_fd = agent->turn_use_tls ? agent->turn_tls_ctx.tcp_socket.fd : agent->turn_tcp_socket.fd;
    if (turn_fd > maxfd) {
      maxfd = turn_fd;
    }
    FD_SET(turn_fd, &rfds);
  }

  ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
  if (ret < 0) {
    LOGE("select error");
  } else if (ret == 0) {
    // timeout
  } else {
    if ((agent->turn_use_tcp || agent->turn_use_tls) &&
        FD_ISSET(agent->turn_use_tls ? agent->turn_tls_ctx.tcp_socket.fd : agent->turn_tcp_socket.fd, &rfds)) {
      tcp_ready = 1;
    }
    if (tcp_ready) {
      memset(buf, 0, len);
      ret = agent_turn_tcp_recv_message(agent, buf, len);
      if (ret > 0 && addr != NULL) {
        memcpy(addr, &agent->turn.server_addr, sizeof(*addr));
      }
      return ret;
    }
    for (i = 0; i < 2; i++) {
      if (FD_ISSET(agent->udp_sockets[i].fd, &rfds)) {
        memset(buf, 0, len);
        ret = udp_socket_recvfrom(&agent->udp_sockets[i], addr, buf, len);
        break;
      }
    }
  }

  return ret;
}

static int agent_socket_recv_attempts(Agent* agent, Address* addr, uint8_t* buf, int len, int maxtimes) {
  int ret = -1;
  int i = 0;
  for (i = 0; i < maxtimes; i++) {
    if ((ret = agent_socket_recv(agent, addr, buf, len)) != 0) {
      break;
    }
  }
  return ret;
}

static int agent_socket_send(Agent* agent, Address* addr, const uint8_t* buf, int len) {
  if ((agent->turn_use_tcp || agent->turn_use_tls) && addr != NULL && addr_equal(addr, &agent->turn.server_addr)) {
    int sent = 0;

    while (sent < len) {
      int ret = agent_turn_stream_send(agent, buf + sent, len - sent);
      if (ret <= 0) {
        return -1;
      }
      sent += ret;
    }
    return sent;
  }

  switch (addr->family) {
    case AF_INET6:
      return udp_socket_sendto(&agent->udp_sockets[1], addr, buf, len);
    case AF_INET:
    default:
      return udp_socket_sendto(&agent->udp_sockets[0], addr, buf, len);
  }
  return -1;
}

static int agent_turn_recv_response(Agent* agent, StunMessage* recv_msg, uint16_t expected_method) {
  Address addr;
  int ret = -1;
  int attempt = 0;

  if (!turn_client_is_enabled(&agent->turn) || recv_msg == NULL) {
    return -1;
  }

  for (attempt = 0; attempt < AGENT_STUN_RECV_MAXTIMES; attempt++) {
    memset(recv_msg, 0, sizeof(*recv_msg));
    ret = agent_socket_recv(agent, &addr, recv_msg->buf, sizeof(recv_msg->buf));
    if (ret <= 0) {
      continue;
    }
    if (stun_probe(recv_msg->buf, ret) != 0) {
      continue;
    }
    recv_msg->size = ret;
    stun_parse_msg_buf(recv_msg);
    if (!addr_equal(&addr, &agent->turn.server_addr)) {
      continue;
    }
    if (recv_msg->stunmethod != expected_method) {
      continue;
    }
    if (recv_msg->stunclass != STUN_CLASS_RESPONSE && recv_msg->stunclass != STUN_CLASS_ERROR) {
      continue;
    }
    return ret;
  }

  return -1;
}

static int agent_turn_stream_recv(Agent* agent, uint8_t* buf, int len) {
  int ret;

  if (agent->turn_use_tls) {
    ret = ssl_transport_recv(&agent->turn_tls_ctx, buf, len);
  } else {
    ret = tcp_socket_recv(&agent->turn_tcp_socket, buf, len);
  }

  if (ret < 0) {
    agent_turn_disable_transport(agent, "TURN stream recv failed");
  }
  return ret;
}

static int agent_turn_stream_send(Agent* agent, const uint8_t* buf, int len) {
  int ret;

  if (agent->turn_use_tls) {
    ret = ssl_transport_send(&agent->turn_tls_ctx, buf, len);
  } else {
    ret = tcp_socket_send(&agent->turn_tcp_socket, buf, len);
  }

  if (ret < 0) {
    agent_turn_disable_transport(agent, "TURN stream send failed");
  }
  return ret;
}

static void agent_turn_disable_transport(Agent* agent, const char* reason) {
  if (agent == NULL) {
    return;
  }

  if (reason != NULL) {
    LOGW("%s", reason);
  }

  if (agent->turn_use_tls) {
    ssl_transport_disconnect(&agent->turn_tls_ctx);
  } else if (agent->turn_tcp_socket.fd >= 0) {
    tcp_socket_close(&agent->turn_tcp_socket);
    agent->turn_tcp_socket.fd = -1;
  }

  agent->turn_use_tls = 0;
  agent->turn_use_tcp = 0;
  agent->turn.enabled = 0;
  agent->turn.allocated = 0;
}

static int agent_turn_tcp_recv_exact(Agent* agent, uint8_t* buf, int len) {
  int received = 0;

  while (received < len) {
    int ret = agent_turn_stream_recv(agent, buf + received, len - received);
    if (ret <= 0) {
      return -1;
    }
    received += ret;
  }

  return received;
}

static int agent_turn_tcp_recv_message(Agent* agent, uint8_t* buf, int len) {
  int ret;
  uint8_t header[4];
  uint16_t channel_number = 0;
  uint16_t message_length = 0;
  int total_length = 0;
  int padded_length = 0;

  if (len < (int)sizeof(StunHeader)) {
    return -1;
  }

  ret = agent_turn_tcp_recv_exact(agent, header, (int)sizeof(header));
  if (ret <= 0) {
    return -1;
  }

  channel_number = ((uint16_t)header[0] << 8) | header[1];
  message_length = ((uint16_t)header[2] << 8) | header[3];

  if ((channel_number & 0xC000u) == 0x4000u) {
    if ((int)message_length > len) {
      return -1;
    }
    ret = agent_turn_tcp_recv_exact(agent, buf, (int)message_length);
    if (ret <= 0) {
      return -1;
    }

    padded_length = (int)((message_length + 3u) & ~3u);
    if (padded_length > (int)message_length) {
      uint8_t padding[3];
      ret = agent_turn_tcp_recv_exact(agent, padding, padded_length - (int)message_length);
      if (ret <= 0) {
        return -1;
      }
    }

    agent->turn_tcp_recv_log_count++;
    if (agent->turn_tcp_recv_log_count <= 3 || (agent->turn_tcp_recv_log_count % 100u) == 0u) {
      LOGI("TURN TCP recv ChannelData channel=0x%04x len=%u count=%" PRIu32,
           channel_number,
           message_length,
           agent->turn_tcp_recv_log_count);
    } else {
      LOGD("TURN TCP recv ChannelData channel=0x%04x len=%u", channel_number, message_length);
    }
    return (int)message_length;
  }

  memcpy(buf, header, sizeof(header));
  ret = agent_turn_tcp_recv_exact(agent, buf + sizeof(header), (int)sizeof(StunHeader) - (int)sizeof(header));
  if (ret <= 0) {
    return -1;
  }

  if (stun_probe(buf, sizeof(StunHeader)) != 0) {
    return -1;
  }

  message_length = ntohs(((StunHeader*)buf)->length);
  total_length = (int)sizeof(StunHeader) + (int)message_length;
  if (total_length > len) {
    return -1;
  }

  if (message_length > 0) {
    ret = agent_turn_tcp_recv_exact(agent, buf + sizeof(StunHeader), (int)message_length);
    if (ret <= 0) {
      return -1;
    }
  }

  agent->turn_tcp_recv_log_count++;
  if (agent->turn_tcp_recv_log_count <= 3 || (agent->turn_tcp_recv_log_count % 500u) == 0u) {
    LOGI("TURN TCP recv STUN len=%d method=0x%04x class=0x%04x count=%" PRIu32,
         total_length,
         ntohs(((StunHeader*)buf)->type) & 0x3EEF,
         ntohs(((StunHeader*)buf)->type) & 0x0110,
         agent->turn_tcp_recv_log_count);
  } else {
    LOGD("TURN TCP recv STUN len=%d method=0x%04x class=0x%04x",
         total_length,
         ntohs(((StunHeader*)buf)->type) & 0x3EEF,
         ntohs(((StunHeader*)buf)->type) & 0x0110);
  }
  return total_length;
}

static int agent_turn_create_permission(Agent* agent, const Address* peer_addr, int force_refresh) {
  StunMessage send_msg;
  StunMessage recv_msg;
  int result = TURN_RESULT_ERROR;
  int retry_count = 0;

  if (!turn_client_is_enabled(&agent->turn) || peer_addr == NULL) {
    return -1;
  }
  if (!force_refresh && turn_client_has_permission(&agent->turn, peer_addr)) {
    return 0;
  }

  do {
    memset(&send_msg, 0, sizeof(send_msg));
    if (turn_build_create_permission_request(&agent->turn, &send_msg, peer_addr) != 0) {
      return -1;
    }
    if (agent_socket_send(agent, &agent->turn.server_addr, send_msg.buf, (int)send_msg.size) < 0) {
      return -1;
    }
    if (agent_turn_recv_response(agent, &recv_msg, TURN_METHOD_CREATE_PERMISSION) <= 0) {
      return -1;
    }
    result = turn_handle_create_permission_response(&agent->turn, &recv_msg, peer_addr);
  } while (result == TURN_RESULT_RETRY_WITH_AUTH && retry_count++ == 0);

  return result == TURN_RESULT_OK ? 0 : -1;
}

int agent_prepare_turn_peer(Agent* agent, const Address* peer_addr) {
  if (agent == NULL || peer_addr == NULL) {
    return -1;
  }
  if (!turn_client_is_enabled(&agent->turn) || !agent->turn.allocated) {
    return 0;
  }
  return agent_turn_create_permission(agent, peer_addr, 0);
}

static int agent_send_to_peer(Agent* agent, const Address* peer_addr, const uint8_t* buf, int len) {
  IceCandidatePair* pair = agent_active_pair(agent);
  StunMessage send_msg;
  int ret = -1;

  if (pair != NULL && pair->local != NULL && pair->local->type == ICE_CANDIDATE_TYPE_RELAY) {
    if (agent_turn_create_permission(agent, peer_addr, 0) != 0) {
      return -1;
    }
    memset(&send_msg, 0, sizeof(send_msg));
    if (turn_build_send_indication(&agent->turn, &send_msg, peer_addr, buf, (size_t)len) != 0) {
      return -1;
    }
    ret = agent_socket_send(agent, &agent->turn.server_addr, send_msg.buf, (int)send_msg.size);
    if (ret >= 0) {
      agent->last_activity_time = ports_get_epoch_time();
    }
    return ret;
  }

  ret = agent_socket_send(agent, (Address*)peer_addr, buf, len);
  if (ret >= 0) {
    agent->last_activity_time = ports_get_epoch_time();
  }
  return ret;
}

static int agent_turn_refresh(Agent* agent) {
  StunMessage send_msg;
  StunMessage recv_msg;
  int result = TURN_RESULT_ERROR;
  int retry_count = 0;

  if (!turn_client_is_enabled(&agent->turn) || !agent->turn.allocated) {
    return 0;
  }

  do {
    memset(&send_msg, 0, sizeof(send_msg));
    if (turn_build_refresh_request(&agent->turn, &send_msg) != 0) {
      return -1;
    }
    if (agent_socket_send(agent, &agent->turn.server_addr, send_msg.buf, (int)send_msg.size) < 0) {
      return -1;
    }
    if (agent_turn_recv_response(agent, &recv_msg, TURN_METHOD_REFRESH) <= 0) {
      return -1;
    }
    result = turn_handle_refresh_response(&agent->turn, &recv_msg);
  } while (result == TURN_RESULT_RETRY_WITH_AUTH && retry_count++ == 0);

  return result == TURN_RESULT_OK ? 0 : -1;
}

int agent_maintain_turn(Agent* agent) {
  IceCandidatePair* pair = NULL;
  uint64_t now_ms = 0;

  if (agent == NULL || !turn_client_is_enabled(&agent->turn) || !agent->turn.allocated) {
    return 0;
  }

  now_ms = ports_get_epoch_time();
  if (turn_client_needs_refresh(&agent->turn, now_ms)) {
    if (agent_turn_refresh(agent) != 0) {
      LOGE("TURN refresh failed");
      return -1;
    }
  }

  pair = agent_active_pair(agent);
  if (pair != NULL &&
      pair->local != NULL &&
      pair->remote != NULL &&
      pair->local->type == ICE_CANDIDATE_TYPE_RELAY) {
    if (turn_client_permission_needs_refresh(&agent->turn, &pair->remote->addr, now_ms)) {
      if (agent_turn_create_permission(agent, &pair->remote->addr, 1) != 0) {
        LOGE("TURN permission refresh failed");
        return -1;
      }
    }
  }

  return 0;
}

static int agent_create_host_addr(Agent* agent) {
  int i, j;
  const char* iface_prefx[] = {CONFIG_IFACE_PREFIX};
  IceCandidate* ice_candidate;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    for (j = 0; j < sizeof(iface_prefx) / sizeof(iface_prefx[0]); j++) {
      ice_candidate = agent->local_candidates + agent->local_candidates_count;
      // only copy port and family to addr of ice candidate
      ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_HOST,
                           &agent->udp_sockets[i].bind_addr);
      // if resolve host addr, add to local candidate
      if (ports_get_host_addr(&ice_candidate->addr, iface_prefx[j])) {
        agent->local_candidates_count++;
      }
    }
  }

  return 0;
}

static int agent_create_stun_addr(Agent* agent, Address* serv_addr) {
  int ret = -1;
  Address bind_addr;
  StunMessage send_msg;
  StunMessage recv_msg;
  memset(&send_msg, 0, sizeof(send_msg));
  memset(&recv_msg, 0, sizeof(recv_msg));

  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);

  ret = agent_socket_send(agent, serv_addr, send_msg.buf, send_msg.size);

  if (ret == -1) {
    LOGE("Failed to send STUN Binding Request.");
    return ret;
  }

  ret = agent_socket_recv_attempts(agent, NULL, recv_msg.buf, sizeof(recv_msg.buf), AGENT_STUN_RECV_MAXTIMES);
  if (ret <= 0) {
    LOGD("Failed to receive STUN Binding Response.");
    return ret;
  }

  stun_parse_msg_buf(&recv_msg);
  memcpy(&bind_addr, &recv_msg.mapped_addr, sizeof(Address));
  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_SRFLX, &bind_addr);
  return ret;
}

static int agent_create_turn_addr(Agent* agent, Address* serv_addr, const char* username, const char* credential) {
  int ret = -1;
  int result = TURN_RESULT_ERROR;
  int retry_count = 0;
  int i = 0;
  StunMessage send_msg;
  StunMessage recv_msg;
  IceCandidate* ice_candidate = NULL;
  IceCandidate* related_candidate = NULL;

  if (username == NULL || credential == NULL || username[0] == '\0' || credential[0] == '\0') {
    LOGW("TURN server credentials are empty");
    return -1;
  }

  turn_client_configure(&agent->turn, serv_addr, username, credential);
  if (!turn_client_is_enabled(&agent->turn)) {
    return -1;
  }

  if (agent->turn_use_tls) {
    if (ssl_transport_connect(&agent->turn_tls_ctx, agent->turn_host, serv_addr->port, NULL) != 0) {
      LOGE("Failed to connect TURN TLS socket");
      return -1;
    }
  } else if (agent->turn_use_tcp) {
    if (tcp_socket_open(&agent->turn_tcp_socket, serv_addr->family) != 0) {
      LOGE("Failed to open TURN TCP socket");
      return -1;
    }
    if (tcp_socket_connect(&agent->turn_tcp_socket, serv_addr) != 0) {
      LOGE("Failed to connect TURN TCP socket");
      tcp_socket_close(&agent->turn_tcp_socket);
      agent->turn_tcp_socket.fd = -1;
      return -1;
    }
  }

  do {
    memset(&send_msg, 0, sizeof(send_msg));
    if (turn_build_allocate_request(&agent->turn, &send_msg, retry_count > 0) != 0) {
      return -1;
    }
    ret = agent_socket_send(agent, serv_addr, send_msg.buf, (int)send_msg.size);
    if (ret < 0) {
      LOGE("Failed to send TURN Allocate request.");
      return -1;
    }
    ret = agent_turn_recv_response(agent, &recv_msg, TURN_METHOD_ALLOCATE);
    if (ret <= 0) {
      LOGD("Failed to receive TURN Allocate response.");
      return ret;
    }
    result = turn_handle_allocate_response(&agent->turn, &recv_msg);
  } while (result == TURN_RESULT_RETRY_WITH_AUTH && retry_count++ == 0);

  if (result != TURN_RESULT_OK) {
    LOGE("TURN Allocate failed");
    return -1;
  }

  ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_RELAY, &agent->turn.relayed_addr);
  for (i = 0; i < agent->local_candidates_count - 1; i++) {
    if (agent->local_candidates[i].type == ICE_CANDIDATE_TYPE_HOST &&
        agent->local_candidates[i].addr.family == ice_candidate->addr.family) {
      related_candidate = &agent->local_candidates[i];
      break;
    }
  }
  if (related_candidate != NULL) {
    memcpy(&ice_candidate->raddr, &related_candidate->addr, sizeof(Address));
  }
  return ret;
}

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential) {
  char* pos;
  int port;
  char hostname[64];
  char addr_string[ADDRSTRLEN];
  int i;
  int scheme_len = 0;
  int addr_type[1] = {AF_INET};  // ipv6 no need stun
  Address resolved_addr;
  memset(hostname, 0, sizeof(hostname));

  if (urls == NULL) {
    agent_create_host_addr(agent);
    return;
  }

  agent->turn_use_tcp = 0;
  agent->turn_use_tls = 0;
  memset(agent->turn_host, 0, sizeof(agent->turn_host));

  if (strncmp(urls, "stun:", 5) == 0 || strncmp(urls, "turn:", 5) == 0) {
    scheme_len = 5;
  } else if (strncmp(urls, "turns:", 6) == 0) {
    scheme_len = 6;
    agent->turn_use_tls = 1;
  } else {
    LOGE("Invalid URL scheme");
    return;
  }

  if (!agent->turn_use_tls && strncmp(urls, "turn:", 5) == 0 && strstr(urls, "transport=tcp") != NULL) {
    agent->turn_use_tcp = 1;
  }

  if ((pos = strstr(urls + scheme_len, ":")) == NULL) {
    LOGE("Invalid URL");
    return;
  }

  port = atoi(pos + 1);
  if (port <= 0) {
    LOGE("Cannot parse port");
    return;
  }

  snprintf(hostname, pos - urls - scheme_len + 1, "%s", urls + scheme_len);
  snprintf(agent->turn_host, sizeof(agent->turn_host), "%s", hostname);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (ports_resolve_addr(hostname, &resolved_addr) == 0) {
      addr_set_port(&resolved_addr, port);
      addr_to_string(&resolved_addr, addr_string, sizeof(addr_string));
      LOGI("Resolved stun/turn server %s:%d", addr_string, port);

      if (strncmp(urls, "stun:", 5) == 0) {
        LOGD("Create stun addr");
        agent_create_stun_addr(agent, &resolved_addr);
      } else if (strncmp(urls, "turn:", 5) == 0 || strncmp(urls, "turns:", 6) == 0) {
        LOGD("Create turn addr");
        agent_create_turn_addr(agent, &resolved_addr, username, credential);
      }
    }
  }
}

void agent_create_ice_credential(Agent* agent) {
  memset(agent->local_ufrag, 0, sizeof(agent->local_ufrag));
  memset(agent->local_upwd, 0, sizeof(agent->local_upwd));

  utils_random_string(agent->local_ufrag, 4);
  utils_random_string(agent->local_upwd, 24);
}

void agent_get_local_description(Agent* agent, char* description, int length) {
  for (int i = 0; i < agent->local_candidates_count; i++) {
    ice_candidate_to_description(&agent->local_candidates[i], description + strlen(description), length - strlen(description));
  }

  // remove last \n
  description[strlen(description)] = '\0';
  LOGD("local description:\n%s", description);
}

int agent_send(Agent* agent, const uint8_t* buf, int len) {
  IceCandidatePair* pair = agent_active_pair(agent);

  if (pair == NULL || pair->remote == NULL) {
    return -1;
  }
  return agent_send_to_peer(agent, &pair->remote->addr, buf, len);
}

static void agent_create_binding_response(Agent* agent, StunMessage* msg, Address* addr) {
  int size = 0;
  char username[584];
  char mapped_address[32];
  uint8_t mask[16];
  StunHeader* header;
  stun_msg_create(msg, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
  header = (StunHeader*)msg->buf;
  memcpy(header->transaction_id, agent->transaction_id, sizeof(header->transaction_id));
  snprintf(username, sizeof(username), "%s:%s", agent->local_ufrag, agent->remote_ufrag);
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, agent->transaction_id, sizeof(agent->transaction_id));
  size = stun_set_mapped_address(mapped_address, mask, addr);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, size, mapped_address);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->local_upwd, strlen(agent->local_upwd));
}

static void agent_create_binding_request(Agent* agent, StunMessage* msg) {
  uint32_t local_priority = 0;
  uint64_t tie_breaker_host = 0;
  uint64_t tie_breaker = 0;
  // send binding request
  stun_msg_create(msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);
  char username[584];
  memset(username, 0, sizeof(username));
  snprintf(username, sizeof(username), "%s:%s", agent->remote_ufrag, agent->local_ufrag);
  local_priority = htonl(agent->nominated_pair->local->priority);
  tie_breaker_host = ((uint64_t)(uint8_t)agent->local_ufrag[0] << 56) |
                     ((uint64_t)(uint8_t)agent->local_ufrag[1] << 48) |
                     ((uint64_t)(uint8_t)agent->local_ufrag[2] << 40) |
                     ((uint64_t)(uint8_t)agent->local_ufrag[3] << 32) |
                     ((uint64_t)(uint8_t)agent->local_upwd[0] << 24) |
                     ((uint64_t)(uint8_t)agent->local_upwd[1] << 16) |
                     ((uint64_t)(uint8_t)agent->local_upwd[2] << 8) |
                     (uint64_t)(uint8_t)agent->local_upwd[3];
  if (tie_breaker_host == 0) {
    tie_breaker_host = 1;
  }
  tie_breaker = agent_htonll(tie_breaker_host);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_PRIORITY, 4, (char*)&local_priority);
  if (agent->mode == AGENT_MODE_CONTROLLING) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USE_CANDIDATE, 0, NULL);
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLING, 8, (char*)&tie_breaker);
  } else {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLED, 8, (char*)&tie_breaker);
  }
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->remote_upwd, strlen(agent->remote_upwd));
}

void agent_process_stun_request(Agent* agent, StunMessage* stun_msg, Address* addr) {
  StunMessage msg;
  StunHeader* header;
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, agent->local_upwd) == 0) {
        header = (StunHeader*)stun_msg->buf;
        memcpy(agent->transaction_id, header->transaction_id, sizeof(header->transaction_id));
        agent_create_binding_response(agent, &msg, addr);
        agent_send_to_peer(agent, addr, msg.buf, (int)msg.size);
        agent->binding_request_time = ports_get_epoch_time();
        agent->last_activity_time = agent->binding_request_time;
      }
      break;
    default:
      break;
  }
}

void agent_process_stun_response(Agent* agent, StunMessage* stun_msg) {
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, agent->remote_upwd) == 0) {
        agent->nominated_pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
      }
      break;
    default:
      break;
  }
}

int agent_recv(Agent* agent, uint8_t* buf, int len) {
  int ret = -1;
  StunMessage stun_msg;
  Address addr;
  Address peer_addr;
  uint8_t* turn_data = NULL;
  size_t turn_data_len = 0;

  ret = agent_socket_recv(agent, &addr, buf, len);
  if (ret > 0) {
    agent->binding_request_time = ports_get_epoch_time();
    agent->last_activity_time = agent->binding_request_time;
  }

  if (ret > 0 && stun_probe(buf, ret) == 0) {
    memcpy(&agent->last_recv_addr, &addr, sizeof(addr));
    memcpy(stun_msg.buf, buf, ret);
    stun_msg.size = ret;
    stun_parse_msg_buf(&stun_msg);

    if (turn_parse_data_indication(&stun_msg, &peer_addr, &turn_data, &turn_data_len) == 0) {
      char peer_addr_str[ADDRSTRLEN];
      addr_to_string(&peer_addr, peer_addr_str, sizeof(peer_addr_str));
      agent->turn_data_indication_log_count++;
      if (agent->turn_data_indication_log_count <= 3 || (agent->turn_data_indication_log_count % 500u) == 0u) {
        LOGI("TURN data indication from=%s:%d len=%u count=%" PRIu32,
             peer_addr_str,
             peer_addr.port,
             (unsigned int)turn_data_len,
             agent->turn_data_indication_log_count);
      } else {
        LOGD("TURN data indication from=%s:%d len=%u",
             peer_addr_str,
             peer_addr.port,
             (unsigned int)turn_data_len);
      }
      if ((int)turn_data_len > len) {
        return -1;
      }
      memmove(buf, turn_data, turn_data_len);
      ret = (int)turn_data_len;
      addr = peer_addr;

      if (stun_probe(buf, ret) != 0) {
        return ret;
      }

      memset(&stun_msg, 0, sizeof(stun_msg));
      memcpy(stun_msg.buf, buf, ret);
      stun_msg.size = ret;
      stun_parse_msg_buf(&stun_msg);
    }

    switch (stun_msg.stunclass) {
      case STUN_CLASS_REQUEST:
        agent_process_stun_request(agent, &stun_msg, &addr);
        break;
      case STUN_CLASS_RESPONSE:
        agent_process_stun_response(agent, &stun_msg);
        break;
      case STUN_CLASS_ERROR:
        break;
      default:
        break;
    }
    ret = 0;
  }
  return ret;
}

void agent_set_remote_description(Agent* agent, char* description) {
  /*
  a=ice-ufrag:Iexb
  a=ice-pwd:IexbSoY7JulyMbjKwISsG9
  a=candidate:1 1 UDP 1 36.231.28.50 38143 typ srflx
  */
  int i;

  LOGD("Set remote description:\n%s", description);

  char* line_start = description;
  char* line_end = NULL;

  while ((line_end = strstr(line_start, "\r\n")) != NULL) {
    if (strncmp(line_start, "a=ice-ufrag:", strlen("a=ice-ufrag:")) == 0) {
      strncpy(agent->remote_ufrag, line_start + strlen("a=ice-ufrag:"), line_end - line_start - strlen("a=ice-ufrag:"));

    } else if (strncmp(line_start, "a=ice-pwd:", strlen("a=ice-pwd:")) == 0) {
      strncpy(agent->remote_upwd, line_start + strlen("a=ice-pwd:"), line_end - line_start - strlen("a=ice-pwd:"));

    } else if (strncmp(line_start, "a=candidate:", strlen("a=candidate:")) == 0) {
      if (ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count], line_start, line_end) == 0) {
        for (i = 0; i < agent->remote_candidates_count; i++) {
          if (strcmp(agent->remote_candidates[i].foundation, agent->remote_candidates[agent->remote_candidates_count].foundation) == 0) {
            break;
          }
        }
        if (i == agent->remote_candidates_count) {
          agent->remote_candidates_count++;
        }
      }
    }

    line_start = line_end + 2;
  }

  LOGD("remote ufrag: %s", agent->remote_ufrag);
  LOGD("remote upwd: %s", agent->remote_upwd);
}

void agent_update_candidate_pairs(Agent* agent) {
  int i, j;
  IceCandidatePair previous_pairs[AGENT_MAX_CANDIDATE_PAIRS];
  int previous_pairs_num = 0;
  IceCandidatePair previous_nominated_pair_snapshot;
  IceCandidatePair previous_selected_pair_snapshot;
  int has_previous_nominated_pair = 0;
  int has_previous_selected_pair = 0;

  if (agent->nominated_pair != NULL) {
    memcpy(&previous_nominated_pair_snapshot, agent->nominated_pair, sizeof(previous_nominated_pair_snapshot));
    has_previous_nominated_pair = 1;
  }
  if (agent->selected_pair != NULL) {
    memcpy(&previous_selected_pair_snapshot, agent->selected_pair, sizeof(previous_selected_pair_snapshot));
    has_previous_selected_pair = 1;
  }

  agent->nominated_pair = NULL;
  agent->selected_pair = NULL;

  if (agent->candidate_pairs_num > 0) {
    previous_pairs_num = agent->candidate_pairs_num;
    if (previous_pairs_num > AGENT_MAX_CANDIDATE_PAIRS) {
      previous_pairs_num = AGENT_MAX_CANDIDATE_PAIRS;
    }
    memcpy(previous_pairs, agent->candidate_pairs, sizeof(IceCandidatePair) * previous_pairs_num);
  }

  agent->candidate_pairs_num = 0;

  // Please set gather candidates before set remote description
  for (i = 0; i < agent->local_candidates_count; i++) {
    for (j = 0; j < agent->remote_candidates_count; j++) {
      if (agent->candidate_pairs_num >= AGENT_MAX_CANDIDATE_PAIRS) {
        LOGW("candidate pair table is full");
        goto done;
      }
      if (agent->local_candidates[i].addr.family == agent->remote_candidates[j].addr.family) {
        int matched = 0;
        IceCandidatePair* previous_pair = NULL;

        agent->candidate_pairs[agent->candidate_pairs_num].local = &agent->local_candidates[i];
        agent->candidate_pairs[agent->candidate_pairs_num].remote = &agent->remote_candidates[j];
        agent->candidate_pairs[agent->candidate_pairs_num].priority = agent->local_candidates[i].priority + agent->remote_candidates[j].priority;
        agent->candidate_pairs[agent->candidate_pairs_num].state = ICE_CANDIDATE_STATE_FROZEN;

        for (int k = 0; k < previous_pairs_num; k++) {
          if (agent_candidate_pair_matches(&previous_pairs[k], &agent->local_candidates[i], &agent->remote_candidates[j])) {
            previous_pair = &previous_pairs[k];
            matched = 1;
            break;
          }
        }

        if (matched && previous_pair != NULL) {
          agent->candidate_pairs[agent->candidate_pairs_num].state = previous_pair->state;
          agent->candidate_pairs[agent->candidate_pairs_num].conncheck = previous_pair->conncheck;
          if (has_previous_nominated_pair &&
              agent_candidate_pair_matches(&previous_nominated_pair_snapshot,
                                           &agent->local_candidates[i],
                                           &agent->remote_candidates[j])) {
            agent->nominated_pair = &agent->candidate_pairs[agent->candidate_pairs_num];
          }
          if (has_previous_selected_pair &&
              agent_candidate_pair_matches(&previous_selected_pair_snapshot,
                                           &agent->local_candidates[i],
                                           &agent->remote_candidates[j])) {
            agent->selected_pair = &agent->candidate_pairs[agent->candidate_pairs_num];
          }
        }

        agent->candidate_pairs_num++;
      }
    }
  }

  if (has_previous_nominated_pair && agent->nominated_pair == NULL) {
    for (i = 0; i < agent->candidate_pairs_num; i++) {
      if (agent_candidate_pair_matches(&previous_nominated_pair_snapshot,
                                       agent->candidate_pairs[i].local,
                                       agent->candidate_pairs[i].remote)) {
        agent->candidate_pairs[i].state = previous_nominated_pair_snapshot.state;
        agent->candidate_pairs[i].conncheck = previous_nominated_pair_snapshot.conncheck;
        agent->nominated_pair = &agent->candidate_pairs[i];
        break;
      }
    }
  }

  if (has_previous_selected_pair && agent->selected_pair == NULL) {
    for (i = 0; i < agent->candidate_pairs_num; i++) {
      if (agent_candidate_pair_matches(&previous_selected_pair_snapshot,
                                       agent->candidate_pairs[i].local,
                                       agent->candidate_pairs[i].remote)) {
        agent->candidate_pairs[i].state = previous_selected_pair_snapshot.state;
        agent->candidate_pairs[i].conncheck = previous_selected_pair_snapshot.conncheck;
        agent->selected_pair = &agent->candidate_pairs[i];
        break;
      }
    }
  }

done:

  LOGD("candidate pairs num: %d", agent->candidate_pairs_num);
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    char local_addr[ADDRSTRLEN];
    char remote_addr[ADDRSTRLEN];

    addr_to_string(&agent->candidate_pairs[i].local->addr, local_addr, sizeof(local_addr));
    addr_to_string(&agent->candidate_pairs[i].remote->addr, remote_addr, sizeof(remote_addr));
    LOGD("candidate pair[%d] priority=%" PRIu32 " local=%s:%d remote=%s:%d",
         i,
         (uint32_t)agent->candidate_pairs[i].priority,
         local_addr,
         agent->candidate_pairs[i].local->addr.port,
         remote_addr,
         agent->candidate_pairs[i].remote->addr.port);
  }
}

int agent_connectivity_check(Agent* agent) {
  char addr_string[ADDRSTRLEN];
  uint8_t buf[1400];
  StunMessage msg;

  if (agent->nominated_pair == NULL) {
    LOGI("nominated pair is null");
    return -1;
  }

  if (agent->nominated_pair->state != ICE_CANDIDATE_STATE_INPROGRESS) {
    LOGI("nominated pair is not in progress");
    return -1;
  }

  memset(&msg, 0, sizeof(msg));

  if (agent->nominated_pair->conncheck % AGENT_CONNCHECK_PERIOD == 0) {
    addr_to_string(&agent->nominated_pair->remote->addr, addr_string, sizeof(addr_string));
    LOGD("send binding request to remote ip: %s, port: %d", addr_string, agent->nominated_pair->remote->addr.port);
    agent_create_binding_request(agent, &msg);
    agent_send_to_peer(agent, &agent->nominated_pair->remote->addr, msg.buf, (int)msg.size);
  }

  agent_recv(agent, buf, sizeof(buf));

  if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent->selected_pair = agent->nominated_pair;
    return 0;
  }

  return -1;
}

int agent_select_candidate_pair(Agent* agent) {
  int i;

  if (agent->nominated_pair != NULL && agent->nominated_pair->state == ICE_CANDIDATE_STATE_INPROGRESS) {
    agent->nominated_pair->conncheck++;
    if (agent->nominated_pair->conncheck < AGENT_CONNCHECK_MAX) {
      return 0;
    }
    agent->nominated_pair->state = ICE_CANDIDATE_STATE_FAILED;
    agent->nominated_pair = NULL;
  }

  if (agent->turn_use_tcp || agent->turn_use_tls) {
    for (i = 0; i < agent->candidate_pairs_num; i++) {
      if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FROZEN &&
          agent_is_relay_relay_pair(&agent->candidate_pairs[i])) {
        agent->nominated_pair = &agent->candidate_pairs[i];
        agent->candidate_pairs[i].conncheck = 0;
        agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_INPROGRESS;
        agent_log_candidate_pair("nominate ICE pair", agent->nominated_pair);
        return 0;
      }
    }
  }

  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FROZEN) {
      // nominate this pair
      agent->nominated_pair = &agent->candidate_pairs[i];
      agent->candidate_pairs[i].conncheck = 0;
      agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_INPROGRESS;
      agent_log_candidate_pair("nominate ICE pair", agent->nominated_pair);
      return 0;
    } else if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FAILED) {
    } else if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      agent->selected_pair = &agent->candidate_pairs[i];
      agent_log_candidate_pair("select ICE pair", agent->selected_pair);
      return 0;
    }
  }
  // all candidate pairs are failed
  return -1;
}
