#ifndef VPN_HANDSHAKE_H
#define VPN_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "config.h"
#include "peer.h"
#include "packet.h"

typedef struct {
    uint8_t  ephemeral_private[VPN_PRIVKEY_LEN];
    uint8_t  chaining_key[VPN_KEY_LEN];
    uint8_t  hash[32];
    uint32_t local_index;
    time_t   timestamp;
} handshake_init_state_t;

/**
 * Initiator creates a Handshake Initiation packet (148 bytes).
 */
int handshake_create_initiation(uint8_t *out_packet, size_t max_len,
                                const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                                const uint8_t my_pubkey[VPN_PUBKEY_LEN],
                                const uint8_t their_pubkey[VPN_PUBKEY_LEN],
                                uint32_t local_index,
                                handshake_init_state_t *out_state);

/**
 * Responder parses and validates a Handshake Initiation packet.
 * Authenticates the sender's static public key against the peer table.
 */
int handshake_consume_initiation(const uint8_t *packet, size_t packet_len,
                                 const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                                 const uint8_t my_pubkey[VPN_PUBKEY_LEN],
                                 vpn_peer_table_t *peer_table,
                                 vpn_peer_t **out_peer,
                                 packet_handshake_init_t *out_parsed,
                                 uint8_t chaining_key[VPN_KEY_LEN],
                                 uint8_t hash[32]);

/**
 * Responder creates a Handshake Response packet (92 bytes) and derives directional keys.
 */
int handshake_create_response(uint8_t *out_packet, size_t max_len,
                              const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                              const uint8_t their_ephemeral[VPN_PUBKEY_LEN],
                              const uint8_t their_static[VPN_PUBKEY_LEN],
                              uint32_t my_index,
                              uint32_t their_index,
                              const uint8_t chaining_key[VPN_KEY_LEN],
                              const uint8_t hash[32],
                              uint8_t send_key[VPN_KEY_LEN],
                              uint8_t recv_key[VPN_KEY_LEN]);

/**
 * Initiator consumes Handshake Response and derives directional keys.
 */
int handshake_consume_response(const uint8_t *packet, size_t packet_len,
                               const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                               const handshake_init_state_t *init_state,
                               const uint8_t their_static[VPN_PUBKEY_LEN],
                               uint32_t *out_peer_index,
                               uint8_t send_key[VPN_KEY_LEN],
                               uint8_t recv_key[VPN_KEY_LEN]);

#endif /* VPN_HANDSHAKE_H */
