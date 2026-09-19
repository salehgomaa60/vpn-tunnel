#ifndef VPN_TUN_H
#define VPN_TUN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "config.h"

#ifdef __linux__
#include <net/if.h>
#else
#define IFNAMSIZ 16
#endif

typedef struct {
    int fd;
    char name[IFNAMSIZ];
    int mtu;
} tun_device_t;

/**
 * Open and allocate a Linux TUN interface.
 * 
 * @param tun       Pointer to tun_device_t struct to populate.
 * @param dev_name  Desired device name (e.g. "vpn0", or NULL for kernel auto-assign).
 * @param mtu       Inner MTU to assign (e.g. VPN_DEFAULT_INNER_MTU).
 * @return          0 on success, negative error code on failure.
 */
int tun_open(tun_device_t *tun, const char *dev_name, int mtu);

/**
 * Configure the IPv4 address and netmask for the TUN interface.
 * 
 * @param tun          Pointer to initialized tun_device_t.
 * @param ip_str       IPv4 address string (e.g. "10.0.0.1").
 * @param netmask_str  Subnet mask string (e.g. "255.255.255.0").
 * @return             0 on success, negative error code on failure.
 */
int tun_set_ip(const tun_device_t *tun, const char *ip_str, const char *netmask_str);

/**
 * Bring the TUN interface UP and RUNNING.
 * 
 * @param tun  Pointer to initialized tun_device_t.
 * @return     0 on success, negative error code on failure.
 */
int tun_set_up(const tun_device_t *tun);

/**
 * Read a raw IP packet from the TUN interface.
 * 
 * @param tun      Pointer to tun_device_t.
 * @param buf      Destination buffer.
 * @param buf_len  Size of destination buffer (must be >= MTU).
 * @return         Number of bytes read, 0 if EAGAIN/EWOULDBLOCK (non-blocking), or -1 on error.
 */
ssize_t tun_read(const tun_device_t *tun, uint8_t *buf, size_t buf_len);

/**
 * Write a raw IP packet to the TUN interface to deliver to the OS network stack.
 * 
 * @param tun      Pointer to tun_device_t.
 * @param buf      Packet buffer to write.
 * @param buf_len  Length of the packet.
 * @return         Number of bytes written, or -1 on error.
 */
ssize_t tun_write(const tun_device_t *tun, const uint8_t *buf, size_t buf_len);

/**
 * Close and release the TUN interface.
 * 
 * @param tun  Pointer to tun_device_t.
 */
void tun_close(tun_device_t *tun);

#endif /* VPN_TUN_H */
