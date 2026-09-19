/*
 * handshake.c — WireGuard-Inspired 1-RTT Noise IK Handshake State Machine
 *
 * PROTOCOL SPECIFICATION & CRYPTOGRAPHIC DESIGN
 * --------------------------------------------
 * This module implements a 1-Round-Trip-Time (1-RTT) authenticated key exchange based on
 * the Noise IK (Initiator Known static key) pattern using Curve25519, ChaCha20-Poly1305,
 * and BLAKE2b.
 *
 * ROLES & KEYS:
 *   Initiator Static (s_i, S_i)  |  Responder Static (s_r, S_r)
 *   Initiator Ephemeral (e_i, E_i)|  Responder Ephemeral (e_r, E_r)
 *
 * STEP-BY-STEP CRYPTOGRAPHIC FLOW:
 * --------------------------------
 * Handshake Initiation Packet (148 bytes, Initiator -> Responder):
 *   1. Initiator generates fresh ephemeral keypair (e_i, E_i).
 *   2. Initializes Chaining Key `c` and Hash `h` with protocol identifiers.
 *   3. Mixes Responder Static `S_r` and Initiator Ephemeral `E_i` into hash `h`.
 *   4. DH1 = X25519(e_i, S_r) -> KDF2 -> derives encryption key `kappa1`.
 *   5. Encrypts Initiator Static Key `S_i` using `kappa1` -> 48 bytes payload.
 *   6. Mixes encrypted static into hash `h`.
 *   7. DH2 = X25519(s_i, S_r) -> KDF2 -> derives encryption key `kappa2`.
 *   8. Encrypts current 12-byte timestamp (8s + 4ns) using `kappa2` -> 28 bytes payload.
 *   9. Computes 16-byte MAC1 over first 108 bytes.
 *
 * Handshake Response Packet (92 bytes, Responder -> Initiator):
 *   1. Responder verifies initiation, decrypts `S_i`, looks up peer, and decrypts timestamp.
 *   2. Responder generates fresh ephemeral keypair (e_r, E_r).
 *   3. DH3 = X25519(e_r, E_i) -> KDF1 -> update chaining key `c`.
 *   4. DH4 = X25519(e_r, S_i) -> KDF2 -> derives encryption key `kappa3`.
 *   5. Encrypts empty payload (auth tag only) using `kappa3` -> 16 bytes payload.
 *   6. Derives final 256-bit directional transport keys:
 *        (key_send, key_recv) = KDF2(c, NULL, 0)
 *      - Responder uses: send_key = key_send, recv_key = key_recv
 *      - Initiator uses: send_key = key_recv, recv_key = key_send
 */

#include "handshake.h"
#include "kdf.h"
#include "crypto.h"
#include "logging.h"
#include <string.h>
#include <errno.h>

static const char PROTOCOL_IDENTIFIER[] = "VPN_Tunnel_Noise_IK_25519_ChaChaPoly_BLAKE2b";
static const char PROTOCOL_LABEL[]      = "VPN_Tunnel_v1_EduZx";

static void mix_hash(uint8_t hash[32], const uint8_t *data, size_t len) {
    uint8_t input[32 + 256];
    if (len > 256) return;

    memcpy(input, hash, 32);
    if (len > 0 && data) {
        memcpy(input + 32, data, len);
    }
    vpn_crypto_hash(hash, input, 32 + len);
    vpn_crypto_memzero(input, sizeof(input));
}

static void init_chaining_and_hash(uint8_t chaining_key[VPN_KEY_LEN], uint8_t hash[32]) {
    vpn_crypto_hash(chaining_key, (const uint8_t *)PROTOCOL_IDENTIFIER, strlen(PROTOCOL_IDENTIFIER));
    vpn_crypto_hash(hash, (const uint8_t *)PROTOCOL_LABEL, strlen(PROTOCOL_LABEL));
}

int handshake_create_initiation(uint8_t *out_packet, size_t max_len,
                                const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                                const uint8_t my_pubkey[VPN_PUBKEY_LEN],
                                const uint8_t their_pubkey[VPN_PUBKEY_LEN],
                                uint32_t local_index,
                                handshake_init_state_t *out_state) {
    if (!out_packet || !my_privkey || !my_pubkey || !their_pubkey || !out_state) {
        return -EINVAL;
    }
    if (max_len < PACKET_HANDSHAKE_INIT_LEN) {
        return -ENOSPC;
    }

    packet_handshake_init_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.sender_index = local_index;

    /* 1. Generate Ephemeral Keypair (e_i, E_i) */
    uint8_t ephemeral_pub[VPN_PUBKEY_LEN];
    vpn_crypto_generate_keypair(ephemeral_pub, out_state->ephemeral_private);
    memcpy(msg.unencrypted_ephemeral, ephemeral_pub, VPN_PUBKEY_LEN);

    /* 2. Initialize Chaining Key and Hash */
    init_chaining_and_hash(out_state->chaining_key, out_state->hash);

    mix_hash(out_state->hash, their_pubkey, VPN_PUBKEY_LEN);
    mix_hash(out_state->hash, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);
    vpn_kdf1(out_state->chaining_key, out_state->chaining_key, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);

    /* 3. DH(e_i, S_r) */
    uint8_t dh1[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh1, their_pubkey, out_state->ephemeral_private) != 0) {
        vpn_crypto_memzero(dh1, sizeof(dh1));
        return -EFAULT;
    }

    uint8_t kappa1[VPN_KEY_LEN];
    vpn_kdf2(out_state->chaining_key, kappa1, out_state->chaining_key, dh1, sizeof(dh1));
    vpn_crypto_memzero(dh1, sizeof(dh1));

    /* 4. Encrypt Static Public Key */
    vpn_crypto_aead_encrypt(msg.encrypted_static, msg.encrypted_static + VPN_PUBKEY_LEN,
                            my_pubkey, VPN_PUBKEY_LEN,
                            out_state->hash, 32, 0, kappa1);
    vpn_crypto_memzero(kappa1, sizeof(kappa1));
    mix_hash(out_state->hash, msg.encrypted_static, sizeof(msg.encrypted_static));

    /* 5. DH(s_i, S_r) */
    uint8_t dh2[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh2, their_pubkey, my_privkey) != 0) {
        vpn_crypto_memzero(dh2, sizeof(dh2));
        return -EFAULT;
    }

    uint8_t kappa2[VPN_KEY_LEN];
    vpn_kdf2(out_state->chaining_key, kappa2, out_state->chaining_key, dh2, sizeof(dh2));
    vpn_crypto_memzero(dh2, sizeof(dh2));

    /* 6. Encrypt Timestamp (12 bytes: 8s + 4ns) */
    uint8_t timestamp_buf[12] = {0};
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    le64_write(timestamp_buf, (uint64_t)ts.tv_sec);
    le32_write(timestamp_buf + 8, (uint32_t)ts.tv_nsec);

    vpn_crypto_aead_encrypt(msg.encrypted_timestamp, msg.encrypted_timestamp + 12,
                            timestamp_buf, 12,
                            out_state->hash, 32, 0, kappa2);
    vpn_crypto_memzero(kappa2, sizeof(kappa2));
    mix_hash(out_state->hash, msg.encrypted_timestamp, sizeof(msg.encrypted_timestamp));

    /* 7. Compute MAC1 (Keyed by HASH(LABEL || their_pubkey)) */
    uint8_t mac_key[32];
    vpn_crypto_hash(mac_key, their_pubkey, VPN_PUBKEY_LEN);
    vpn_crypto_mac16(msg.mac1, mac_key, sizeof(mac_key), msg.unencrypted_ephemeral, 108);

    out_state->local_index = local_index;
    out_state->timestamp = ts.tv_sec;

    return packet_serialize_handshake_init(out_packet, max_len, &msg);
}

int handshake_consume_initiation(const uint8_t *packet, size_t packet_len,
                                 const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                                 const uint8_t my_pubkey[VPN_PUBKEY_LEN],
                                 vpn_peer_table_t *peer_table,
                                 vpn_peer_t **out_peer,
                                 packet_handshake_init_t *out_parsed,
                                 uint8_t chaining_key[VPN_KEY_LEN],
                                 uint8_t hash[32]) {
    if (!packet || !my_privkey || !my_pubkey || !peer_table || !out_peer || !out_parsed || !chaining_key || !hash) {
        return -EINVAL;
    }

    int rc = packet_parse_handshake_init(packet, packet_len, out_parsed);
    if (rc != 0) {
        return rc;
    }

    init_chaining_and_hash(chaining_key, hash);

    mix_hash(hash, my_pubkey, VPN_PUBKEY_LEN);
    mix_hash(hash, out_parsed->unencrypted_ephemeral, VPN_PUBKEY_LEN);
    vpn_kdf1(chaining_key, chaining_key, out_parsed->unencrypted_ephemeral, VPN_PUBKEY_LEN);

    /* 1. DH(s_r, E_i) */
    uint8_t dh1[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh1, out_parsed->unencrypted_ephemeral, my_privkey) != 0) {
        vpn_crypto_memzero(dh1, sizeof(dh1));
        return -EBADMSG;
    }

    uint8_t kappa1[VPN_KEY_LEN];
    vpn_kdf2(chaining_key, kappa1, chaining_key, dh1, sizeof(dh1));
    vpn_crypto_memzero(dh1, sizeof(dh1));

    /* 2. Decrypt Peer Static Public Key */
    uint8_t their_static[VPN_PUBKEY_LEN];
    if (vpn_crypto_aead_decrypt(their_static, out_parsed->encrypted_static, VPN_PUBKEY_LEN,
                                out_parsed->encrypted_static + VPN_PUBKEY_LEN,
                                hash, 32, 0, kappa1) != 0) {
        vpn_crypto_memzero(kappa1, sizeof(kappa1));
        LOG_WARN("handshake_consume_initiation: Failed to decrypt static key");
        return -EBADMSG;
    }
    vpn_crypto_memzero(kappa1, sizeof(kappa1));

    /* 3. Lookup Peer in Table */
    vpn_peer_t *peer = peer_find_by_pubkey(peer_table, their_static);
    if (!peer) {
        LOG_WARN("handshake_consume_initiation: Unknown peer public key");
        return -EACCES;
    }

    mix_hash(hash, out_parsed->encrypted_static, sizeof(out_parsed->encrypted_static));

    /* 4. DH(s_r, S_i) */
    uint8_t dh2[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh2, their_static, my_privkey) != 0) {
        vpn_crypto_memzero(dh2, sizeof(dh2));
        return -EBADMSG;
    }

    uint8_t kappa2[VPN_KEY_LEN];
    vpn_kdf2(chaining_key, kappa2, chaining_key, dh2, sizeof(dh2));
    vpn_crypto_memzero(dh2, sizeof(dh2));

    /* 5. Decrypt Timestamp */
    uint8_t timestamp_buf[12];
    if (vpn_crypto_aead_decrypt(timestamp_buf, out_parsed->encrypted_timestamp, 12,
                                out_parsed->encrypted_timestamp + 12,
                                hash, 32, 0, kappa2) != 0) {
        vpn_crypto_memzero(kappa2, sizeof(kappa2));
        LOG_WARN("handshake_consume_initiation: Failed to decrypt timestamp");
        return -EBADMSG;
    }
    vpn_crypto_memzero(kappa2, sizeof(kappa2));

    uint64_t sec = le64_read(timestamp_buf);
    if (peer->last_handshake_time != 0 && (time_t)sec <= peer->last_handshake_time) {
        LOG_WARN("handshake_consume_initiation: Replayed or stale handshake timestamp (%lu <= %lu)",
                 (unsigned long)sec, (unsigned long)peer->last_handshake_time);
        return -EBADMSG;
    }

    mix_hash(hash, out_parsed->encrypted_timestamp, sizeof(out_parsed->encrypted_timestamp));

    *out_peer = peer;
    return 0;
}

int handshake_create_response(uint8_t *out_packet, size_t max_len,
                              const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                              const uint8_t their_ephemeral[VPN_PUBKEY_LEN],
                              const uint8_t their_static[VPN_PUBKEY_LEN],
                              uint32_t my_index,
                              uint32_t their_index,
                              const uint8_t chaining_key[VPN_KEY_LEN],
                              const uint8_t hash[32],
                              uint8_t send_key[VPN_KEY_LEN],
                              uint8_t recv_key[VPN_KEY_LEN]) {
    if (!out_packet || !my_privkey || !their_ephemeral || !their_static || !chaining_key || !hash || !send_key || !recv_key) {
        return -EINVAL;
    }
    if (max_len < PACKET_HANDSHAKE_RESP_LEN) {
        return -ENOSPC;
    }

    packet_handshake_resp_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.sender_index = my_index;
    msg.receiver_index = their_index;

    /* 1. Generate Ephemeral Keypair (e_r, E_r) */
    uint8_t ephemeral_priv[VPN_PRIVKEY_LEN];
    uint8_t ephemeral_pub[VPN_PUBKEY_LEN];
    vpn_crypto_generate_keypair(ephemeral_pub, ephemeral_priv);
    memcpy(msg.unencrypted_ephemeral, ephemeral_pub, VPN_PUBKEY_LEN);

    uint8_t c[VPN_KEY_LEN];
    uint8_t h[32];
    memcpy(c, chaining_key, VPN_KEY_LEN);
    memcpy(h, hash, 32);

    mix_hash(h, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);
    vpn_kdf1(c, c, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);

    /* 2. DH(e_r, E_i) */
    uint8_t dh1[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh1, their_ephemeral, ephemeral_priv) != 0) {
        vpn_crypto_memzero(dh1, sizeof(dh1));
        vpn_crypto_memzero(ephemeral_priv, sizeof(ephemeral_priv));
        return -EFAULT;
    }
    vpn_kdf1(c, c, dh1, sizeof(dh1));
    vpn_crypto_memzero(dh1, sizeof(dh1));

    /* 3. DH(e_r, S_i) */
    uint8_t dh2[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh2, their_static, ephemeral_priv) != 0) {
        vpn_crypto_memzero(dh2, sizeof(dh2));
        vpn_crypto_memzero(ephemeral_priv, sizeof(ephemeral_priv));
        return -EFAULT;
    }
    vpn_crypto_memzero(ephemeral_priv, sizeof(ephemeral_priv));

    uint8_t kappa[VPN_KEY_LEN];
    vpn_kdf2(c, kappa, c, dh2, sizeof(dh2));
    vpn_crypto_memzero(dh2, sizeof(dh2));

    /* 4. Encrypt Empty Auth */
    vpn_crypto_aead_encrypt(NULL, msg.encrypted_nothing, NULL, 0, h, 32, 0, kappa);
    vpn_crypto_memzero(kappa, sizeof(kappa));
    mix_hash(h, msg.encrypted_nothing, sizeof(msg.encrypted_nothing));

    /* 5. Derive Directional Transport Keys:
     * (key_send, key_recv) = KDF2(c, empty)
     * For Responder: send_key = key_send, recv_key = key_recv */
    vpn_kdf2(send_key, recv_key, c, NULL, 0);

    /* 6. Compute MAC1 */
    uint8_t mac_key[32];
    vpn_crypto_hash(mac_key, their_static, VPN_PUBKEY_LEN);
    vpn_crypto_mac16(msg.mac1, mac_key, sizeof(mac_key), msg.unencrypted_ephemeral, 52);

    vpn_crypto_memzero(c, sizeof(c));
    vpn_crypto_memzero(h, sizeof(h));

    return packet_serialize_handshake_resp(out_packet, max_len, &msg);
}

int handshake_consume_response(const uint8_t *packet, size_t packet_len,
                               const uint8_t my_privkey[VPN_PRIVKEY_LEN],
                               const handshake_init_state_t *init_state,
                               const uint8_t their_static[VPN_PUBKEY_LEN],
                               uint32_t *out_peer_index,
                               uint8_t send_key[VPN_KEY_LEN],
                               uint8_t recv_key[VPN_KEY_LEN]) {
    if (!packet || !my_privkey || !init_state || !their_static || !out_peer_index || !send_key || !recv_key) {
        return -EINVAL;
    }

    packet_handshake_resp_t msg;
    int rc = packet_parse_handshake_resp(packet, packet_len, &msg);
    if (rc != 0) {
        return rc;
    }

    if (msg.receiver_index != init_state->local_index) {
        LOG_WARN("handshake_consume_response: Receiver index mismatch (%u != %u)",
                 msg.receiver_index, init_state->local_index);
        return -EBADMSG;
    }

    uint8_t c[VPN_KEY_LEN];
    uint8_t h[32];
    memcpy(c, init_state->chaining_key, VPN_KEY_LEN);
    memcpy(h, init_state->hash, 32);

    mix_hash(h, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);
    vpn_kdf1(c, c, msg.unencrypted_ephemeral, VPN_PUBKEY_LEN);

    /* 1. DH(e_i, E_r) */
    uint8_t dh1[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh1, msg.unencrypted_ephemeral, init_state->ephemeral_private) != 0) {
        vpn_crypto_memzero(dh1, sizeof(dh1));
        return -EBADMSG;
    }
    vpn_kdf1(c, c, dh1, sizeof(dh1));
    vpn_crypto_memzero(dh1, sizeof(dh1));

    /* 2. DH(s_i, E_r) */
    uint8_t dh2[VPN_KEY_LEN];
    if (vpn_crypto_dh(dh2, msg.unencrypted_ephemeral, my_privkey) != 0) {
        vpn_crypto_memzero(dh2, sizeof(dh2));
        return -EBADMSG;
    }

    uint8_t kappa[VPN_KEY_LEN];
    vpn_kdf2(c, kappa, c, dh2, sizeof(dh2));
    vpn_crypto_memzero(dh2, sizeof(dh2));

    /* 3. Decrypt Empty Auth */
    if (vpn_crypto_aead_decrypt(NULL, NULL, 0, msg.encrypted_nothing, h, 32, 0, kappa) != 0) {
        vpn_crypto_memzero(kappa, sizeof(kappa));
        LOG_WARN("handshake_consume_response: Authentication failed on response empty payload");
        return -EBADMSG;
    }
    vpn_crypto_memzero(kappa, sizeof(kappa));

    mix_hash(h, msg.encrypted_nothing, sizeof(msg.encrypted_nothing));

    /* 4. Derive Directional Transport Keys:
     * (key_send, key_recv) = KDF2(c, empty)
     * For Initiator: send_key = key_recv, recv_key = key_send */
    uint8_t key_send[VPN_KEY_LEN], key_recv[VPN_KEY_LEN];
    vpn_kdf2(key_send, key_recv, c, NULL, 0);

    memcpy(send_key, key_recv, VPN_KEY_LEN);
    memcpy(recv_key, key_send, VPN_KEY_LEN);

    vpn_crypto_memzero(key_send, sizeof(key_send));
    vpn_crypto_memzero(key_recv, sizeof(key_recv));
    vpn_crypto_memzero(c, sizeof(c));
    vpn_crypto_memzero(h, sizeof(h));

    *out_peer_index = msg.sender_index;
    return 0;
}
