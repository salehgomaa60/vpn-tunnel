#include "config.h"
#include "crypto.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int config_parse_key_hex(const char *hex_str, uint8_t key[VPN_KEY_LEN]) {
    if (!hex_str || !key) return -EINVAL;

    size_t len = strlen(hex_str);
    if (len != 64) {
        LOG_ERROR("config_parse_key_hex: Invalid hex key length %zu (expected 64)", len);
        return -EINVAL;
    }

    for (size_t i = 0; i < 32; i++) {
        unsigned int byte_val = 0;
        if (sscanf(hex_str + (i * 2), "%02x", &byte_val) != 1) {
            LOG_ERROR("config_parse_key_hex: Invalid hex character at index %zu", i * 2);
            return -EINVAL;
        }
        key[i] = (uint8_t)byte_val;
    }

    return 0;
}

int config_key_to_hex(const uint8_t key[VPN_KEY_LEN], char hex_str[65]) {
    if (!key || !hex_str) return -EINVAL;

    for (size_t i = 0; i < 32; i++) {
        snprintf(hex_str + (i * 2), 3, "%02x", key[i]);
    }
    hex_str[64] = '\0';
    return 0;
}
