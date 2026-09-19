#ifndef VPN_PEER_H
#define VPN_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "config.h"
#include "transport.h"
#include "routing.h"
#include "replay.h"

typedef enum {
    SESSION_STATE_NONE        = 0,
    SESSION_STATE_HANDSHAKING = 1,
    SESSION_STATE_ESTABLISHED = 2,
    SESSION_STATE_REKEYING    = 3
} session_state_t;

typedef struct {
    uint32_t local_index;               /* Local receiver index for this session */
    uint32_t peer_index;                /* Remote receiver index */
    session_state_t state;              /* Session state lifecycle */
    uint8_t send_key[VPN_KEY_LEN];      /* Key for outgoing AEAD encryption */
    uint8_t recv_key[VPN_KEY_LEN];      /* Key for incoming AEAD decryption */
    uint64_t sending_counter;           /* Monotonic sending counter (starts at 0) */
    replay_filter_t replay_filter;      /* Inbound sliding-window replay filter */
    time_t established_time;            /* Timestamp when session was established */
    time_t last_packet_sent;            /* Last transmission timestamp */
    time_t last_packet_recv;            /* Last reception timestamp */
} vpn_session_t;

typedef struct {
    char name[64];
    uint8_t public_key[VPN_PUBKEY_LEN];
    vpn_endpoint_t endpoint;            /* Current observed network endpoint */
    vpn_cidr_t allowed_ips[VPN_MAX_CIDRS_PER_PEER];
    int allowed_ips_count;
    vpn_session_t current_session;
    vpn_session_t previous_session;     /* Kept temporarily for smooth rekey transition */
    time_t last_handshake_time;
} vpn_peer_t;

typedef struct {
    vpn_peer_t peers[VPN_MAX_PEERS];
    int peer_count;
    uint32_t next_local_index;          /* Monotonic index generator */
} vpn_peer_table_t;

/**
 * Initialize a peer table.
 */
void peer_table_init(vpn_peer_table_t *table);

/**
 * Register a new peer in the peer table.
 */
vpn_peer_t *peer_add(vpn_peer_table_t *table, const char *name,
                     const uint8_t public_key[VPN_PUBKEY_LEN],
                     const vpn_endpoint_t *initial_endpoint);

/**
 * Add an AllowedIPs CIDR to a peer.
 */
int peer_add_allowed_ip(vpn_peer_t *peer, const char *cidr_str);

/**
 * Check if a source IP is authorized for this peer.
 */
int peer_allows_source_ip(const vpn_peer_t *peer, uint32_t src_ip);

/**
 * Find a peer by static public key.
 */
vpn_peer_t *peer_find_by_pubkey(vpn_peer_table_t *table, const uint8_t public_key[VPN_PUBKEY_LEN]);

/**
 * Find a peer and matching session by receiver index.
 */
vpn_peer_t *peer_find_by_index(vpn_peer_table_t *table, uint32_t receiver_index, vpn_session_t **out_session);

/**
 * Find the destination peer for an outbound IP packet (Cryptographic Routing).
 */
vpn_peer_t *peer_find_by_dest_ip(vpn_peer_table_t *table, uint32_t dest_ip);

/**
 * Update peer endpoint on NAT roaming.
 */
int peer_update_endpoint(vpn_peer_t *peer, const vpn_endpoint_t *new_ep);

/**
 * Establish or rotate a session for a peer with fresh directional keys.
 */
void peer_init_session(vpn_peer_t *peer, uint32_t local_idx, uint32_t peer_idx,
                       const uint8_t send_key[VPN_KEY_LEN],
                       const uint8_t recv_key[VPN_KEY_LEN]);

/**
 * Destroy and wipe sensitive key material for a session.
 */
void peer_destroy_session(vpn_session_t *session);

/**
 * Wipe and clean up entire peer table.
 */
void peer_table_destroy(vpn_peer_table_t *table);

#endif /* VPN_PEER_H */
