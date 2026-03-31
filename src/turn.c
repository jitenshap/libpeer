#include <inttypes.h>
#include <string.h>

#include "ports.h"
#include "turn.h"
#include "utils.h"

#define TURN_ATTR_TYPE_XOR_PEER_ADDRESS 0x0012
#define TURN_ATTR_TYPE_DATA 0x0013
static int turn_is_stun_error_with_auth(const StunMessage* msg) {
  if (msg == NULL) {
    return 0;
  }
  if (msg->stunclass != STUN_CLASS_ERROR) {
    return 0;
  }
  if (msg->nonce[0] == '\0' || msg->realm[0] == '\0') {
    return 0;
  }
  return 1;
}

static int turn_write_xor_address(StunMessage* msg, uint16_t type, const Address* addr) {
  char value[32];
  uint8_t mask[16];
  StunHeader* header = NULL;
  int size = 0;

  if (msg == NULL || addr == NULL) {
    return -1;
  }

  memset(value, 0, sizeof(value));
  memset(mask, 0, sizeof(mask));
  header = (StunHeader*)msg->buf;
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, header->transaction_id, sizeof(header->transaction_id));
  size = stun_set_mapped_address(value, mask, (Address*)addr);
  return stun_msg_write_attr(msg, (StunAttrType)type, (uint16_t)size, value);
}

void turn_client_init(TurnClient* client) {
  if (client == NULL) {
    return;
  }
  memset(client, 0, sizeof(*client));
}

void turn_client_configure(TurnClient* client, const Address* server_addr, const char* username, const char* credential) {
  if (client == NULL || server_addr == NULL) {
    return;
  }

  turn_client_init(client);
  memcpy(&client->server_addr, server_addr, sizeof(*server_addr));
  if (username != NULL) {
    strncpy(client->username, username, sizeof(client->username) - 1);
  }
  if (credential != NULL) {
    strncpy(client->credential, credential, sizeof(client->credential) - 1);
  }
  client->enabled = (client->username[0] != '\0' && client->credential[0] != '\0');
}

int turn_client_is_enabled(const TurnClient* client) {
  return client != NULL && client->enabled;
}

int turn_client_has_permission(const TurnClient* client, const Address* peer_addr) {
  int i = 0;

  if (client == NULL || peer_addr == NULL || client->permission_count <= 0) {
    return 0;
  }
  for (i = 0; i < client->permission_count; i++) {
    if (addr_equal(&client->permission_addrs[i], peer_addr)) {
      return 1;
    }
  }
  return 0;
}

int turn_client_needs_refresh(const TurnClient* client, uint64_t now_ms) {
  uint64_t lifetime_ms = 0;
  uint64_t refresh_interval_ms = 0;

  if (!turn_client_is_enabled(client) || !client->allocated) {
    return 0;
  }

  lifetime_ms = client->lifetime > 0 ? (uint64_t)client->lifetime * 1000ULL : 60000ULL;
  refresh_interval_ms = lifetime_ms / 2ULL;
  if (refresh_interval_ms < 15000ULL) {
    refresh_interval_ms = 15000ULL;
  }

  return (now_ms - client->allocation_updated_ms) >= refresh_interval_ms;
}

int turn_client_permission_needs_refresh(const TurnClient* client, const Address* peer_addr, uint64_t now_ms) {
  int i = 0;

  if (!turn_client_is_enabled(client) || peer_addr == NULL) {
    return 0;
  }

  for (i = 0; i < client->permission_count; i++) {
    if (addr_equal(&client->permission_addrs[i], peer_addr)) {
      return (now_ms - client->permission_updated_ms[i]) >= 120000ULL;
    }
  }

  return 1;
}

int turn_build_allocate_request(TurnClient* client, StunMessage* msg, int authenticated) {
  uint32_t requested_transport = htonl(0x11000000);

  if (!turn_client_is_enabled(client) || msg == NULL) {
    return -1;
  }

  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_REQUEST | TURN_METHOD_ALLOCATE);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(requested_transport), (char*)&requested_transport);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, (uint16_t)strlen(client->username), client->username);

  if (authenticated) {
    if (client->realm[0] == '\0' || client->nonce[0] == '\0') {
      return -1;
    }
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_NONCE, (uint16_t)strlen(client->nonce), client->nonce);
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_REALM, (uint16_t)strlen(client->realm), client->realm);
    stun_msg_finish(msg, STUN_CREDENTIAL_LONG_TERM, client->credential, strlen(client->credential));
  }

  return 0;
}

int turn_handle_allocate_response(TurnClient* client, const StunMessage* msg) {
  if (!turn_client_is_enabled(client) || msg == NULL) {
    return TURN_RESULT_ERROR;
  }

  if (msg->stunclass == STUN_CLASS_RESPONSE && (uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_ALLOCATE) {
    memcpy(&client->relayed_addr, &msg->relayed_addr, sizeof(Address));
    memcpy(&client->mapped_addr, &msg->mapped_addr, sizeof(Address));
    client->lifetime = msg->lifetime;
    client->allocation_updated_ms = ports_get_epoch_time();
    client->allocated = 1;
    LOGI("TURN allocate success lifetime=%" PRIu32 "s", client->lifetime);
    return TURN_RESULT_OK;
  }

  if ((uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_ALLOCATE && turn_is_stun_error_with_auth(msg)) {
    LOGW("TURN allocate auth challenge error=%" PRIu32 " realm=%s nonce_len=%u",
         msg->error_code,
         msg->realm,
         (unsigned int)strlen(msg->nonce));
    strncpy(client->realm, msg->realm, sizeof(client->realm) - 1);
    strncpy(client->nonce, msg->nonce, sizeof(client->nonce) - 1);
    return TURN_RESULT_RETRY_WITH_AUTH;
  }

  if ((uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_ALLOCATE) {
    LOGE("TURN allocate failed error=%" PRIu32 " class=0x%04x realm=%s nonce_len=%u",
         msg->error_code,
         (unsigned int)msg->stunclass,
         msg->realm,
         (unsigned int)strlen(msg->nonce));
  }

  return TURN_RESULT_ERROR;
}

int turn_build_refresh_request(TurnClient* client, StunMessage* msg) {
  uint32_t lifetime = 0;

  if (!turn_client_is_enabled(client) || msg == NULL) {
    return -1;
  }
  if (client->realm[0] == '\0' || client->nonce[0] == '\0') {
    return -1;
  }

  lifetime = htonl(client->lifetime > 0 ? client->lifetime : 600U);

  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_REQUEST | TURN_METHOD_REFRESH);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, (uint16_t)strlen(client->username), client->username);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_LIFETIME, sizeof(lifetime), (char*)&lifetime);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_NONCE, (uint16_t)strlen(client->nonce), client->nonce);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_REALM, (uint16_t)strlen(client->realm), client->realm);
  stun_msg_finish(msg, STUN_CREDENTIAL_LONG_TERM, client->credential, strlen(client->credential));
  return 0;
}

int turn_handle_refresh_response(TurnClient* client, const StunMessage* msg) {
  if (!turn_client_is_enabled(client) || msg == NULL) {
    return TURN_RESULT_ERROR;
  }

  if (msg->stunclass == STUN_CLASS_RESPONSE && (uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_REFRESH) {
    if (msg->lifetime > 0) {
      client->lifetime = msg->lifetime;
    }
    client->allocation_updated_ms = ports_get_epoch_time();
    LOGI("TURN refresh success lifetime=%" PRIu32 "s", client->lifetime);
    return TURN_RESULT_OK;
  }

  if ((uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_REFRESH && turn_is_stun_error_with_auth(msg)) {
    LOGW("TURN refresh auth challenge error=%" PRIu32 " realm=%s nonce_len=%u",
         msg->error_code,
         msg->realm,
         (unsigned int)strlen(msg->nonce));
    strncpy(client->realm, msg->realm, sizeof(client->realm) - 1);
    strncpy(client->nonce, msg->nonce, sizeof(client->nonce) - 1);
    return TURN_RESULT_RETRY_WITH_AUTH;
  }

  return TURN_RESULT_ERROR;
}

int turn_build_create_permission_request(TurnClient* client, StunMessage* msg, const Address* peer_addr) {
  if (!turn_client_is_enabled(client) || msg == NULL || peer_addr == NULL) {
    return -1;
  }
  if (client->realm[0] == '\0' || client->nonce[0] == '\0') {
    return -1;
  }

  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_REQUEST | TURN_METHOD_CREATE_PERMISSION);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, (uint16_t)strlen(client->username), client->username);
  turn_write_xor_address(msg, TURN_ATTR_TYPE_XOR_PEER_ADDRESS, peer_addr);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_NONCE, (uint16_t)strlen(client->nonce), client->nonce);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_REALM, (uint16_t)strlen(client->realm), client->realm);
  stun_msg_finish(msg, STUN_CREDENTIAL_LONG_TERM, client->credential, strlen(client->credential));
  return 0;
}

int turn_handle_create_permission_response(TurnClient* client, const StunMessage* msg, const Address* peer_addr) {
  if (!turn_client_is_enabled(client) || msg == NULL || peer_addr == NULL) {
    return TURN_RESULT_ERROR;
  }

  if (msg->stunclass == STUN_CLASS_RESPONSE && (uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_CREATE_PERMISSION) {
    for (int i = 0; i < client->permission_count; i++) {
      if (addr_equal(&client->permission_addrs[i], peer_addr)) {
        client->permission_updated_ms[i] = ports_get_epoch_time();
        return TURN_RESULT_OK;
      }
    }
    if (client->permission_count < TURN_MAX_PERMISSIONS) {
      memcpy(&client->permission_addrs[client->permission_count], peer_addr, sizeof(*peer_addr));
      client->permission_updated_ms[client->permission_count] = ports_get_epoch_time();
      client->permission_count++;
    }
    return TURN_RESULT_OK;
  }

  if ((uint16_t)msg->stunmethod == (uint16_t)TURN_METHOD_CREATE_PERMISSION && turn_is_stun_error_with_auth(msg)) {
    LOGW("TURN permission auth challenge error=%" PRIu32 " realm=%s nonce_len=%u",
         msg->error_code,
         msg->realm,
         (unsigned int)strlen(msg->nonce));
    strncpy(client->realm, msg->realm, sizeof(client->realm) - 1);
    strncpy(client->nonce, msg->nonce, sizeof(client->nonce) - 1);
    return TURN_RESULT_RETRY_WITH_AUTH;
  }

  return TURN_RESULT_ERROR;
}

int turn_build_send_indication(TurnClient* client, StunMessage* msg, const Address* peer_addr, const uint8_t* data, size_t len) {
  if (!turn_client_is_enabled(client) || msg == NULL || peer_addr == NULL || data == NULL || len == 0) {
    return -1;
  }
  if (len > STUN_ATTR_BUF_SIZE - sizeof(StunHeader) - 128) {
    return -1;
  }

  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_INDICATION | TURN_METHOD_SEND);
  turn_write_xor_address(msg, TURN_ATTR_TYPE_XOR_PEER_ADDRESS, peer_addr);
  stun_msg_write_attr(msg, (StunAttrType)TURN_ATTR_TYPE_DATA, (uint16_t)len, (char*)data);
  return 0;
}

int turn_parse_data_indication(StunMessage* msg, Address* peer_addr, uint8_t** data, size_t* data_len) {
  int pos = sizeof(StunHeader);
  int end = 0;
  uint8_t mask[16];
  int have_peer = 0;
  int have_data = 0;

  if (msg == NULL || peer_addr == NULL || data == NULL || data_len == NULL) {
    return -1;
  }
  if (msg->stunclass != STUN_CLASS_INDICATION || (uint16_t)msg->stunmethod != (uint16_t)TURN_METHOD_DATA) {
    return -1;
  }

  memset(mask, 0, sizeof(mask));
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, ((StunHeader*)msg->buf)->transaction_id, sizeof(((StunHeader*)msg->buf)->transaction_id));
  end = ntohs(((StunHeader*)msg->buf)->length) + (int)sizeof(StunHeader);

  while (pos < end) {
    StunAttribute* attr = (StunAttribute*)(msg->buf + pos);
    uint16_t type = ntohs(attr->type);
    uint16_t length = ntohs(attr->length);

    switch (type) {
      case TURN_ATTR_TYPE_XOR_PEER_ADDRESS:
        stun_get_mapped_address(attr->value, mask, peer_addr);
        have_peer = 1;
        break;
      case TURN_ATTR_TYPE_DATA:
        *data = (uint8_t*)attr->value;
        *data_len = length;
        have_data = 1;
        break;
      default:
        break;
    }

    pos += sizeof(StunAttribute) + 4 * ((length + 3) / 4);
  }

  if (!have_peer || !have_data) {
    return -1;
  }

  return 0;
}
