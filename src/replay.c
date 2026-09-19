/*
 * replay.c — Anti-Replay Sliding Window Protection
 *
 * ANTI-REPLAY SLIDING WINDOW SPECIFICATION
 * ---------------------------------------
 * An attacker who intercepts valid encrypted VPN packets on the network can record
 * and retransmit (replay) them later. Even though the attacker cannot read or modify
 * the encrypted payload, replaying legitimate packets can disrupt TCP streams, duplicate
 * state changes, or cause Denial of Service.
 *
 * SLIDING WINDOW MECHANISM (2048-Bit Window)
 * -------------------------------------------
 *  - Each peer tracks the highest authenticated packet counter (`last_counter`).
 *  - A 2048-bit sliding window bitmap (`uint64_t bitmap[32]`) tracks received sequence numbers
 *    in the range `[last_counter - 2047, last_counter]`.
 *  - Bit 0 of `bitmap[0]` represents `last_counter`.
 *  - Bit K represents packet with sequence `last_counter - K`.
 *
 * CRITICAL SECURITY INVARIANT (Two-Phase Verification)
 * ---------------------------------------------------
 *  1. `replay_check()` is called BEFORE AEAD decryption.
 *     - If counter is replayed or too old -> DROP packet immediately (saves CPU time).
 *     - DO NOT update state here because the packet is not yet authenticated!
 *
 *  2. AEAD Decryption (`vpn_crypto_aead_decrypt()`) is performed.
 *     - If decryption fails -> tag mismatch, packet dropped, filter unchanged.
 *
 *  3. `replay_update()` is called ONLY AFTER AEAD decryption succeeds.
 *     - If updated BEFORE decryption, an unauthenticated attacker could inject a fake packet
 *       with counter = `last_counter + 1,000,000`, forcing the window to jump forward and
 *       dropping all valid packets from the legitimate peer!
 */

#include "replay.h"
#include <string.h>

/* =========================================================================
 * replay_init
 *
 * Initialize or clear the replay filter structure.
 * Sets `last_counter` to 0 and zeros out the 2048-bit bitmap array.
 * ========================================================================= */
void replay_init(replay_filter_t *filter) {
    if (filter) {
        memset(filter, 0, sizeof(*filter));
    }
}

/* =========================================================================
 * replay_check
 *
 * Check whether an incoming sequence counter is valid (unseen and within window).
 *
 * PARAMETERS:
 *   filter  : pointer to peer's replay filter state.
 *   counter : 64-bit sequence counter read from unauthenticated packet header.
 *
 * LOGIC:
 *   - counter > last_counter : Packet is strictly newer than highest counter -> ACCEPT.
 *   - diff >= 2048           : Packet is older than window capacity -> REJECT (stale).
 *   - diff < 2048            : Check bitmap bit (diff / 64, diff % 64).
 *                               If bit == 1 -> REJECT (replay).
 *                               If bit == 0 -> ACCEPT (valid out-of-order packet).
 *
 * RETURN:
 *   1 if counter is acceptable, 0 if rejected (replayed or stale).
 * ========================================================================= */
int replay_check(const replay_filter_t *filter, uint64_t counter) {
    if (!filter) return 0;

    /* First packet ever received on this session (last_counter == 0, bitmap == 0) */
    if (filter->last_counter == 0 && filter->bitmap[0] == 0) {
        return 1;
    }

    if (counter > filter->last_counter) {
        return 1; /* Counter is ahead of current window -> valid new packet */
    }

    uint64_t diff = filter->last_counter - counter;
    if (diff >= VPN_REPLAY_WINDOW_SIZE) {
        return 0; /* Counter is too old / outside the 2048-packet window */
    }

    size_t word_idx = (size_t)(diff / 64);
    size_t bit_idx  = (size_t)(diff % 64);

    if ((filter->bitmap[word_idx] & (1ULL << bit_idx)) != 0) {
        return 0; /* Bit already set: this counter was seen previously (REPLAY) */
    }

    return 1; /* Acceptable out-of-order packet */
}

/* =========================================================================
 * replay_update
 *
 * Mark a counter as received and slide the bitmap window if necessary.
 *
 * MUST ONLY BE CALLED AFTER AEAD AUTHENTICATION DECIPHERING SUCCEEDS!
 *
 * PARAMETERS:
 *   filter  : pointer to peer's replay filter.
 *   counter : authenticated 64-bit sequence counter.
 * ========================================================================= */
void replay_update(replay_filter_t *filter, uint64_t counter) {
    if (!filter) return;

    /* First authenticated packet update */
    if (filter->last_counter == 0 && filter->bitmap[0] == 0) {
        filter->last_counter = counter;
        filter->bitmap[0] = 1ULL;
        return;
    }

    if (counter > filter->last_counter) {
        uint64_t diff = counter - filter->last_counter;

        if (diff < VPN_REPLAY_WINDOW_SIZE) {
            /* Slide the 2048-bit bitmap to the right by `diff` bits */
            size_t word_shift = (size_t)(diff / 64);
            size_t bit_shift  = (size_t)(diff % 64);

            uint64_t new_bitmap[VPN_REPLAY_BITMAP_WORDS] = {0};

            for (size_t i = 0; i < VPN_REPLAY_BITMAP_WORDS; i++) {
                if (i >= word_shift) {
                    new_bitmap[i] = filter->bitmap[i - word_shift] << bit_shift;
                    if (bit_shift > 0 && i > word_shift) {
                        new_bitmap[i] |= filter->bitmap[i - word_shift - 1] >> (64 - bit_shift);
                    }
                }
            }

            memcpy(filter->bitmap, new_bitmap, sizeof(filter->bitmap));
        } else {
            /* Large counter jump: entire 2048-bit window was passed over -> reset bitmap */
            memset(filter->bitmap, 0, sizeof(filter->bitmap));
        }

        filter->bitmap[0] |= 1ULL; /* Set bit 0 for the new highest counter */
        filter->last_counter = counter;
    } else {
        /* Out-of-order packet within existing window: set corresponding bit */
        uint64_t diff = filter->last_counter - counter;
        if (diff < VPN_REPLAY_WINDOW_SIZE) {
            size_t word_idx = (size_t)(diff / 64);
            size_t bit_idx  = (size_t)(diff % 64);
            filter->bitmap[word_idx] |= (1ULL << bit_idx);
        }
    }
}

