/*
 * peer.c — Peer Management, Cryptographic Routing, and Session State
 *
 * PEER MANAGEMENT & SESSION STATE MACHINE
 * ---------------------------------------
 * In a WireGuard-inspired VPN architecture:
 *   1. Peer Table: Stores static public keys, current UDP endpoints, allowed IP networks,
 *      and active session state for registered tunnel peers.
 *   2. Session Lifecycle: Each active connection maintains a pair of directional 256-bit AEAD keys
 *      (`send_key` and `recv_key`), a monotonic sending counter, and an anti-replay filter.
 *   3. Cryptographic Routing (AllowedIPs):
 *      - Outbound: Look up target peer by matching destination IP against configured CIDR prefixes.
 *      - Inbound: Verify that decrypted source IP belongs to peer's AllowedIPs range before
 *        delivering to the OS TUN interface (prevents IP spoofing).
 *   4. Endpoint Roaming (NAT Traversal):
 *      - When a valid, authenticated packet arrives from a peer's new IP/Port, update `peer->endpoint`.
 *        This allows clients to switch Wi-Fi/cellular networks seamlessly without reconnecting.
 */

#include "peer.h"
#include "crypto.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void peer_table_init(vpn_peer_table_t *table) {
    if (table) {
        memset(table, 0, sizeof(*table));
        table->next_local_index = 1; /* 0 is reserved as invalid index */
    }
}

vpn_peer_t *peer_add(vpn_peer_table_t *table, const char *name,
                     const uint8_t public_key[VPN_PUBKEY_LEN],
                     const vpn_endpoint_t *initial_endpoint) {
    if (!table || !name || !public_key) {
        return NULL;
    }

    if (table->peer_count >= VPN_MAX_PEERS) {
        LOG_ERROR("peer_add: Maximum peer capacity (%d) reached", VPN_MAX_PEERS);
        return NULL;
    }

    /* Check for duplicate public key */
    for (int i = 0; i < table->peer_count; i++) {
        if (vpn_crypto_memcmp(table->peers[i].public_key, public_key, VPN_PUBKEY_LEN) == 0) {
            LOG_WARN("peer_add: Peer with specified public key already exists");
            return NULL;
        }
    }

    vpn_peer_t *peer = &table->peers[table->peer_count++];
    memset(peer, 0, sizeof(*peer));
    snprintf(peer->name, sizeof(peer->name), "%s", name);
    memcpy(peer->public_key, public_key, VPN_PUBKEY_LEN);

    if (initial_endpoint) {
        peer->endpoint = *initial_endpoint;
    }

    LOG_INFO("peer_add: Added peer '%s' (total %d)", peer->name, table->peer_count);
    return peer;
}

int peer_add_allowed_ip(vpn_peer_t *peer, const char *cidr_str) {
    if (!peer || !cidr_str) {
        return -EINVAL;
    }

    if (peer->allowed_ips_count >= VPN_MAX_CIDRS_PER_PEER) {
        LOG_WARN("peer_add_allowed_ip: Max AllowedIPs reached for peer %s", peer->name);
        return -ENOSPC;
    }

    vpn_cidr_t cidr;
    int rc = vpn_cidr_parse(cidr_str, &cidr);
    if (rc != 0) {
        LOG_ERROR("peer_add_allowed_ip: Failed to parse CIDR '%s'", cidr_str);
        return rc;
    }

    peer->allowed_ips[peer->allowed_ips_count++] = cidr;
    LOG_INFO("peer_add_allowed_ip: Added CIDR '%s' to peer '%s'", cidr_str, peer->name);
    return 0;
}

int peer_allows_source_ip(const vpn_peer_t *peer, uint32_t src_ip) {
    if (!peer) return 0;
    for (int i = 0; i < peer->allowed_ips_count; i++) {
        if (vpn_cidr_match(&peer->allowed_ips[i], src_ip)) {
            return 1;
        }
    }
    return 0;
}

vpn_peer_t *peer_find_by_pubkey(vpn_peer_table_t *table, const uint8_t public_key[VPN_PUBKEY_LEN]) {
    if (!table || !public_key) return NULL;
    for (int i = 0; i < table->peer_count; i++) {
        if (vpn_crypto_memcmp(table->peers[i].public_key, public_key, VPN_PUBKEY_LEN) == 0) {
            return &table->peers[i];
        }
    }
    return NULL;
}

vpn_peer_t *peer_find_by_index(vpn_peer_table_t *table, uint32_t receiver_index, vpn_session_t **out_session) {
    if (!table || receiver_index == 0) return NULL;

    for (int i = 0; i < table->peer_count; i++) {
        vpn_peer_t *p = &table->peers[i];

        if (p->current_session.state == SESSION_STATE_ESTABLISHED &&
            p->current_session.local_index == receiver_index) {
            if (out_session) *out_session = &p->current_session;
            return p;
        }

        if (p->previous_session.state == SESSION_STATE_ESTABLISHED &&
            p->previous_session.local_index == receiver_index) {
            if (out_session) *out_session = &p->previous_session;
            return p;
        }
    }

    return NULL;
}

vpn_peer_t *peer_find_by_dest_ip(vpn_peer_table_t *table, uint32_t dest_ip) {
    if (!table) return NULL;

    /* First matching peer in definition order */
    for (int i = 0; i < table->peer_count; i++) {
        if (peer_allows_source_ip(&table->peers[i], dest_ip)) {
            return &table->peers[i];
        }
    }

    return NULL;
}

int peer_update_endpoint(vpn_peer_t *peer, const vpn_endpoint_t *new_ep) {
    if (!peer || !new_ep) return -EINVAL;

    if (!endpoint_equal(&peer->endpoint, new_ep)) {
        char old_str[64] = "none";
        char new_str[64] = "none";
        endpoint_to_string(&peer->endpoint, old_str, sizeof(old_str));
        endpoint_to_string(new_ep, new_str, sizeof(new_str));

        LOG_INFO("peer_update_endpoint: Peer '%s' ROAMED from %s to %s",
                 peer->name, old_str, new_str);
        peer->endpoint = *new_ep;
        return 1; /* Roamed */
    }

    return 0; /* Unchanged */
}

void peer_init_session(vpn_peer_t *peer, uint32_t local_idx, uint32_t peer_idx,
                       const uint8_t send_key[VPN_KEY_LEN],
                       const uint8_t recv_key[VPN_KEY_LEN]) {
    if (!peer || !send_key || !recv_key) return;

    /* If there is an existing session, preserve it as previous session for transition */
    if (peer->current_session.state == SESSION_STATE_ESTABLISHED) {
        peer_destroy_session(&peer->previous_session);
        peer->previous_session = peer->current_session;
    }

    memset(&peer->current_session, 0, sizeof(peer->current_session));
    peer->current_session.local_index = local_idx;
    peer->current_session.peer_index = peer_idx;
    peer->current_session.state = SESSION_STATE_ESTABLISHED;
    memcpy(peer->current_session.send_key, send_key, VPN_KEY_LEN);
    memcpy(peer->current_session.recv_key, recv_key, VPN_KEY_LEN);
    peer->current_session.sending_counter = 0;
    replay_init(&peer->current_session.replay_filter);
    peer->current_session.established_time = time(NULL);

    peer->last_handshake_time = time(NULL);
    LOG_INFO("peer_init_session: Session established for peer '%s' (local_idx=%u, peer_idx=%u)",
             peer->name, local_idx, peer_idx);
}

void peer_destroy_session(vpn_session_t *session) {
    if (session && session->state != SESSION_STATE_NONE) {
        vpn_crypto_memzero(session->send_key, sizeof(session->send_key));
        vpn_crypto_memzero(session->recv_key, sizeof(session->recv_key));
        memset(session, 0, sizeof(*session));
        session->state = SESSION_STATE_NONE;
    }
}

void peer_table_destroy(vpn_peer_table_t *table) {
    if (!table) return;

    for (int i = 0; i < table->peer_count; i++) {
        peer_destroy_session(&table->peers[i].current_session);
        peer_destroy_session(&table->peers[i].previous_session);
    }
    memset(table, 0, sizeof(*table));
}
