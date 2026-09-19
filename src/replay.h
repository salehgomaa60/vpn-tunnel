#ifndef VPN_REPLAY_H
#define VPN_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#define VPN_REPLAY_BITMAP_WORDS  32  /* 32 * 64 = 2048-bit sliding window */
#define VPN_REPLAY_WINDOW_SIZE   (VPN_REPLAY_BITMAP_WORDS * 64)

typedef struct {
    uint64_t last_counter;
    uint64_t bitmap[VPN_REPLAY_BITMAP_WORDS];
} replay_filter_t;

/**
 * Initialize / reset the replay protection filter.
 */
void replay_init(replay_filter_t *filter);

/**
 * Check whether a packet sequence counter is acceptable.
 * Must be checked BEFORE cryptographic decryption.
 * 
 * @param filter   Pointer to replay filter.
 * @param counter  Incoming packet sequence counter.
 * @return         1 if counter is valid (not seen, within window), 0 if replayed or stale.
 */
int replay_check(const replay_filter_t *filter, uint64_t counter);

/**
 * Update the replay filter to mark a counter as seen.
 * SECURITY RULE: MUST only be called AFTER successful AEAD authentication!
 * 
 * @param filter   Pointer to replay filter.
 * @param counter  Authenticated sequence counter.
 */
void replay_update(replay_filter_t *filter, uint64_t counter);

#endif /* VPN_REPLAY_H */
