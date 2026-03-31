#ifndef TURN_H_
#define TURN_H_

#include <stddef.h>
#include <stdint.h>

#include "address.h"
#include "stun.h"

typedef enum TurnMethod {
  TURN_METHOD_ALLOCATE = STUN_METHOD_ALLOCATE,
  TURN_METHOD_REFRESH = 0x0004,
  TURN_METHOD_SEND = 0x0006,
  TURN_METHOD_DATA = 0x0007,
  TURN_METHOD_CREATE_PERMISSION = 0x0008,
  TURN_METHOD_CHANNEL_BIND = 0x0009,
} TurnMethod;

typedef enum TurnResult {
  TURN_RESULT_ERROR = -1,
  TURN_RESULT_OK = 0,
  TURN_RESULT_RETRY_WITH_AUTH = 1,
} TurnResult;

#ifndef TURN_MAX_PERMISSIONS
#define TURN_MAX_PERMISSIONS 8
#endif

typedef struct TurnClient {
  int enabled;
  int allocated;
  Address server_addr;
  Address relayed_addr;
  Address mapped_addr;
  Address permission_addrs[TURN_MAX_PERMISSIONS];
  uint64_t permission_updated_ms[TURN_MAX_PERMISSIONS];
  int permission_count;
  char username[128];
  char credential[128];
  char realm[64];
  char nonce[64];
  uint32_t lifetime;
  uint64_t allocation_updated_ms;
} TurnClient;

void turn_client_init(TurnClient* client);

void turn_client_configure(TurnClient* client, const Address* server_addr, const char* username, const char* credential);

int turn_client_is_enabled(const TurnClient* client);

int turn_client_has_permission(const TurnClient* client, const Address* peer_addr);

int turn_client_needs_refresh(const TurnClient* client, uint64_t now_ms);

int turn_client_permission_needs_refresh(const TurnClient* client, const Address* peer_addr, uint64_t now_ms);

int turn_build_allocate_request(TurnClient* client, StunMessage* msg, int authenticated);

int turn_handle_allocate_response(TurnClient* client, const StunMessage* msg);

int turn_build_refresh_request(TurnClient* client, StunMessage* msg);

int turn_handle_refresh_response(TurnClient* client, const StunMessage* msg);

int turn_build_create_permission_request(TurnClient* client, StunMessage* msg, const Address* peer_addr);

int turn_handle_create_permission_response(TurnClient* client, const StunMessage* msg, const Address* peer_addr);

int turn_build_send_indication(TurnClient* client, StunMessage* msg, const Address* peer_addr, const uint8_t* data, size_t len);

int turn_parse_data_indication(StunMessage* msg, Address* peer_addr, uint8_t** data, size_t* data_len);

#endif  // TURN_H_
