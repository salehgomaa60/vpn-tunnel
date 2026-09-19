/*
 * main.c — Main Event Loop and VPN Tunnel Orchestrator
 *
 * EDUCATIONAL ARCHITECTURE OVERVIEW
 * ---------------------------------
 * This main file orchestrates the entire VPN daemon using a non-blocking `poll()` event loop.
 * It ties together all subsystems:
 *   - UDP Transport Socket (`transport.c`)
 *   - Linux TUN Virtual Network Interface (`tun.c`)
 *   - WireGuard-Inspired Crypto Handshake & KDF (`handshake.c`, `kdf.c`, `crypto.c`)
 *   - Packet Serialization & Zero-Copy Parsing (`packet.c`)
 *   - Cryptographic Peer Table & AllowedIPs Routing (`peer.c`, `routing.c`)
 *   - Anti-Replay Sliding Window (`replay.c`)
 *
 * EVENT LOOP DUAL PIPELINE:
 * -------------------------
 *               +------------------------+
 *               |   POSIX poll() Loop    |
 *               +-----------+------------+
 *                           |
 *             +-------------+-------------+
 *             |                           |
 *    [POLLIN on UDP Socket]      [POLLIN on TUN Device]
 *             |                           |
 *             v                           v
 *   1. transport_recv()         1. tun_read() (Cleartext IP)
 *   2. packet_peek_type()       2. Extract Dest IP (offset 16)
 *   3. Parse & Lookup Peer      3. Cryptographic Routing lookup
 *   4. Replay Check             4. Increment sending counter
 *   5. AEAD Decrypt             5. AEAD Encrypt payload
 *   6. Replay Update            6. Serialize DATA Wire Packet
 *   7. Endpoint Roam Update     7. transport_send() via UDP
 *   8. AllowedIPs Check
 *   9. tun_write() to OS
 */

#include "config.h"
#include "crypto.h"
#include "logging.h"
#include "tun.h"
#include "transport.h"
#include "packet.h"
#include "peer.h"
#include "handshake.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char **argv) {
    uint16_t listen_port = VPN_DEFAULT_PORT;
    const char *tun_name = VPN_DEFAULT_TUN_NAME;
    const char *tun_ip = "10.0.0.1";
    const char *tun_netmask = "255.255.255.0";

    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        log_set_level(LOG_LEVEL_DEBUG);
    } else {
        log_set_level(LOG_LEVEL_INFO);
    }

    LOG_INFO("=== Educational Linux VPN Tunnel Daemon Starting ===");

    /* Initialize Cryptography Library (libsodium) */
    if (vpn_crypto_init() != 0) {
        LOG_ERROR("Failed to initialize libsodium");
        return 1;
    }

    /* Setup Signal Handling for Graceful Termination (SIGINT / SIGTERM) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Generate Host Static X25519 Keypair (s_host, S_host) */
    uint8_t static_pub[VPN_PUBKEY_LEN];
    uint8_t static_priv[VPN_PRIVKEY_LEN];
    vpn_crypto_generate_keypair(static_pub, static_priv);

    char pub_hex[65];
    config_key_to_hex(static_pub, pub_hex);
    LOG_INFO("Host Static Public Key: %s", pub_hex);

    /* Initialize Peer Table */
    vpn_peer_table_t peer_table;
    peer_table_init(&peer_table);

    /* Open UDP Transport Socket (Default Port 51820) */
    int sock_fd = transport_open(NULL, listen_port);
    if (sock_fd < 0) {
        LOG_ERROR("Failed to bind UDP transport socket on port %u", listen_port);
        vpn_crypto_memzero(static_priv, sizeof(static_priv));
        return 1;
    }

    /* Open Linux TUN Virtual Network Interface */
    tun_device_t tun;
    int tun_rc = tun_open(&tun, tun_name, VPN_DEFAULT_INNER_MTU);
    if (tun_rc == 0) {
        tun_set_ip(&tun, tun_ip, tun_netmask);
        tun_set_up(&tun);
    } else {
        LOG_WARN("Could not open TUN device (%s) - running in socket-only/test mode", strerror(-tun_rc));
    }

    /* Configure pollfd array for event loop multiplexing */
    struct pollfd fds[2];
    int num_fds = 0;

    fds[0].fd = sock_fd;
    fds[0].events = POLLIN;
    num_fds = 1;

    if (tun.fd >= 0) {
        fds[1].fd = tun.fd;
        fds[1].events = POLLIN;
        num_fds = 2;
    }

    /* Statically allocated stack buffers for zero-heap I/O */
    uint8_t net_buf[VPN_MAX_PACKET_SIZE];
    uint8_t tun_buf[VPN_MAX_PACKET_SIZE];
    uint8_t plain_buf[VPN_MAX_PACKET_SIZE];
    uint8_t cipher_buf[VPN_MAX_PACKET_SIZE];

    LOG_INFO("Event loop started. Press Ctrl+C to terminate.");

    while (g_running) {
        int poll_rc = poll(fds, (nfds_t)num_fds, 1000 /* 1-second timeout for periodic checks */);
        if (poll_rc < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll() error: %s", strerror(errno));
            break;
        }

        /* -----------------------------------------------------------------
         * 1. INBOUND UDP NETWORK DATAGRAM EVENT
         * ----------------------------------------------------------------- */
        if (fds[0].revents & POLLIN) {
            vpn_endpoint_t src_ep;
            ssize_t n = transport_recv(sock_fd, &src_ep, net_buf, sizeof(net_buf));
            if (n > 0) {
                packet_type_t ptype = packet_peek_type(net_buf, (size_t)n);

                /* --- Handshake Initiation (0x01) --- */
                if (ptype == PACKET_TYPE_HANDSHAKE_INIT) {
                    vpn_peer_t *peer = NULL;
                    packet_handshake_init_t parsed_init;
                    uint8_t chaining_key[VPN_KEY_LEN];
                    uint8_t hash[32];

                    if (handshake_consume_initiation(net_buf, (size_t)n, static_priv, static_pub,
                                                     &peer_table, &peer, &parsed_init,
                                                     chaining_key, hash) == 0 && peer) {
                        uint8_t resp_packet[PACKET_HANDSHAKE_RESP_LEN];
                        uint32_t my_local_idx = peer_table.next_local_index++;
                        uint8_t send_key[VPN_KEY_LEN], recv_key[VPN_KEY_LEN];

                        int rlen = handshake_create_response(resp_packet, sizeof(resp_packet),
                                                             static_priv,
                                                             parsed_init.unencrypted_ephemeral,
                                                             peer->public_key,
                                                             my_local_idx,
                                                             parsed_init.sender_index,
                                                             chaining_key, hash,
                                                             send_key, recv_key);
                        if (rlen > 0) {
                            peer_init_session(peer, my_local_idx, parsed_init.sender_index, send_key, recv_key);
                            peer_update_endpoint(peer, &src_ep);
                            transport_send(sock_fd, &src_ep, resp_packet, (size_t)rlen);
                        }
                        vpn_crypto_memzero(send_key, sizeof(send_key));
                        vpn_crypto_memzero(recv_key, sizeof(recv_key));
                    }
                }
                /* --- Data (0x03) or Keepalive (0x04) --- */
                else if (ptype == PACKET_TYPE_DATA || ptype == PACKET_TYPE_KEEPALIVE) {
                    packet_data_t parsed_data;
                    if (packet_parse_data(net_buf, (size_t)n, &parsed_data) == 0) {
                        vpn_session_t *session = NULL;
                        vpn_peer_t *peer = peer_find_by_index(&peer_table, parsed_data.receiver_index, &session);

                        if (peer && session && session->state == SESSION_STATE_ESTABLISHED) {
                            /* Anti-Replay Pre-Check (BEFORE decryption) */
                            if (replay_check(&session->replay_filter, parsed_data.counter)) {
                                if (vpn_crypto_aead_decrypt(plain_buf,
                                                            parsed_data.ciphertext,
                                                            parsed_data.ciphertext_len,
                                                            parsed_data.auth_tag,
                                                            NULL, 0,
                                                            parsed_data.counter,
                                                            session->recv_key) == 0) {
                                    /* Cryptographic Authentication Succeeded: Update Replay Window & Endpoint */
                                    replay_update(&session->replay_filter, parsed_data.counter);
                                    peer_update_endpoint(peer, &src_ep);

                                    if (parsed_data.ciphertext_len >= 20 && tun.fd >= 0) {
                                        /* Extract IPv4 Source Address from decrypted packet (bytes 12..15) */
                                        uint32_t src_ip = ((uint32_t)plain_buf[12] << 24) |
                                                          ((uint32_t)plain_buf[13] << 16) |
                                                          ((uint32_t)plain_buf[14] << 8)  |
                                                          ((uint32_t)plain_buf[15]);

                                        /* Inbound Cryptographic Routing Check */
                                        if (peer_allows_source_ip(peer, src_ip)) {
                                            tun_write(&tun, plain_buf, parsed_data.ciphertext_len);
                                        } else {
                                            LOG_WARN("Inbound packet dropped: source IP unauthorized for peer %s",
                                                     peer->name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        /* -----------------------------------------------------------------
         * 2. OUTBOUND TUN PACKET EVENT
         * ----------------------------------------------------------------- */
        if (num_fds > 1 && (fds[1].revents & POLLIN)) {
            ssize_t n = tun_read(&tun, tun_buf, sizeof(tun_buf));
            if (n >= 20) { /* Minimum IPv4 header length */
                /* Extract IPv4 Destination Address (offset 16..19) */
                uint32_t dest_ip = ((uint32_t)tun_buf[16] << 24) |
                                  ((uint32_t)tun_buf[17] << 16) |
                                  ((uint32_t)tun_buf[18] << 8)  |
                                  ((uint32_t)tun_buf[19]);

                /* Outbound Cryptographic Routing Lookup */
                vpn_peer_t *peer = peer_find_by_dest_ip(&peer_table, dest_ip);
                if (peer && peer->current_session.state == SESSION_STATE_ESTABLISHED) {
                    uint8_t tag[VPN_AUTH_TAG_LEN];
                    uint64_t counter = peer->current_session.sending_counter++;

                    if (vpn_crypto_aead_encrypt(cipher_buf, tag, tun_buf, (size_t)n,
                                                NULL, 0, counter,
                                                peer->current_session.send_key) == 0) {
                        int pkt_len = packet_serialize_data(net_buf, sizeof(net_buf),
                                                            peer->current_session.peer_index,
                                                            counter,
                                                            cipher_buf, (size_t)n,
                                                            tag);
                        if (pkt_len > 0) {
                            transport_send(sock_fd, &peer->endpoint, net_buf, (size_t)pkt_len);
                        }
                    }
                }
            }
        }
    }

    LOG_INFO("Daemon shutting down gracefully...");

    /* Cleanup Resources & Securely Wipe Sensitive Secret Keys */
    peer_table_destroy(&peer_table);
    transport_close(&sock_fd);
    tun_close(&tun);
    vpn_crypto_memzero(static_priv, sizeof(static_priv));

    LOG_INFO("Shutdown complete.");
    return 0;
}

