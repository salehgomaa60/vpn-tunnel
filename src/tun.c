/*
 * tun.c — Linux TUN (Network Tunnel) Virtual Device Interface
 *
 * EDUCATIONAL OVERVIEW
 * --------------------
 * A TUN (Network TUNnel) interface is a virtual Layer-3 network device provided by
 * the Linux kernel. Unlike physical network cards (eth0, wlan0) or TAP devices (Layer-2
 * Ethernet frames), a TUN device operates strictly on raw IP packets (Layer-3 IPv4/IPv6).
 *
 * PIPELINE / DATA FLOW
 * --------------------
 *  Outbound Flow (Local Application -> Internet/VPN Remote):
 *    1. Local app sends IPv4 packet (e.g. ping 10.0.0.2).
 *    2. Kernel routing table routes packet to virtual interface (e.g. `vpn0`).
 *    3. Kernel writes raw IPv4 packet into `/dev/net/tun`.
 *    4. VPN daemon reads packet via `tun_read()`.
 *    5. VPN daemon encrypts packet and sends via UDP (`transport_send()`).
 *
 *  Inbound Flow (VPN Remote -> Local Application):
 *    1. VPN daemon receives UDP datagram via `transport_recv()`.
 *    2. VPN daemon decrypts and authenticates packet (AEAD Poly1305 tag check).
 *    3. VPN daemon writes decrypted raw IPv4 packet into `/dev/net/tun` via `tun_write()`.
 *    4. Linux kernel receives raw packet as if it arrived from a physical network cable.
 *    5. Kernel delivers packet to local application socket.
 */

#include "tun.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#endif

/* =========================================================================
 * tun_open
 *
 * Allocate and configure a Linux TUN virtual device.
 *
 * PARAMETERS:
 *   tun      : pointer to `tun_device_t` structure to initialize.
 *   dev_name : requested interface name (e.g. "vpn0"). If NULL or "", kernel auto-assigns "tun0".
 *   mtu      : maximum transmission unit in bytes (typically 1440 for VPNs).
 *
 * SYSTEM CALLS USED:
 *   open("/dev/net/tun", O_RDWR | O_NONBLOCK) : opens Linux TUN character device.
 *   ioctl(fd, TUNSETIFF, &ifr)                 : binds file descriptor to named TUN device.
 *   ioctl(sock, SIOCSIFMTU, &ifr)             : sets interface MTU.
 *
 * RETURN:
 *   0 on success, negative error code on failure (-EINVAL, -errno, -ENOSYS).
 * ========================================================================= */
int tun_open(tun_device_t *tun, const char *dev_name, int mtu) {
    if (!tun) {
        LOG_ERROR("tun_open: NULL tun pointer");
        return -EINVAL;
    }

    if (mtu < VPN_MIN_IPV4_MTU || mtu > VPN_MAX_PACKET_SIZE) {
        LOG_ERROR("tun_open: Invalid MTU %d (must be between %d and %d)",
                  mtu, VPN_MIN_IPV4_MTU, VPN_MAX_PACKET_SIZE);
        return -EINVAL;
    }

    memset(tun, 0, sizeof(*tun));
    tun->fd = -1;
    tun->mtu = mtu;

#ifdef __linux__
    struct ifreq ifr;

    /* Open the Linux TUN/TAP clone device node */
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR("tun_open: Failed to open /dev/net/tun: %s", strerror(errno));
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));

    /*
     * IFF_TUN   : Layer-3 IP packet interface (not IFF_TAP Ethernet frames).
     * IFF_NO_PI : "No Packet Information" header flag. Without this, Linux prepends
     *              a 4-byte header (flags + proto) to every read packet. With IFF_NO_PI,
     *              the buffer starts directly at byte 0 of the IPv4/IPv6 header.
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (dev_name && dev_name[0] != '\0') {
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
    }

    /* Bind file descriptor to requested network interface */
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        LOG_ERROR("tun_open: ioctl(TUNSETIFF) failed: %s", strerror(errno));
        int err = -errno;
        close(fd);
        return err;
    }

    tun->fd = fd;
    snprintf(tun->name, sizeof(tun->name), "%s", ifr.ifr_name);

    /* Set MTU using a temporary control socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        ifr.ifr_mtu = mtu;
        if (ioctl(sock, SIOCSIFMTU, (void *)&ifr) < 0) {
            LOG_WARN("tun_open: Failed to set MTU to %d: %s", mtu, strerror(errno));
        } else {
            LOG_INFO("tun_open: Created TUN interface %s with MTU %d", tun->name, mtu);
        }
        close(sock);
    }

    return 0;
#else
    LOG_ERROR("tun_open: TUN interfaces are only supported natively on Linux");
    return -ENOSYS;
#endif
}

/* =========================================================================
 * tun_set_ip
 *
 * Assign an IPv4 address and netmask to the TUN interface.
 *
 * PARAMETERS:
 *   tun         : initialized TUN device pointer.
 *   ip_str      : IPv4 string (e.g. "10.0.0.1").
 *   netmask_str : Netmask string (e.g. "255.255.255.0").
 * ========================================================================= */
int tun_set_ip(const tun_device_t *tun, const char *ip_str, const char *netmask_str) {
    if (!tun || tun->fd < 0 || !ip_str || !netmask_str) {
        LOG_ERROR("tun_set_ip: Invalid arguments");
        return -EINVAL;
    }

#ifdef __linux__
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR("tun_set_ip: Failed to open socket: %s", strerror(errno));
        return -errno;
    }

    struct ifreq ifr;
    struct sockaddr_in *addr;

    /* Set IP Address (SIOCSIFADDR ioctl) */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", tun->name);
    addr = (struct sockaddr_in *)(void *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &addr->sin_addr) <= 0) {
        LOG_ERROR("tun_set_ip: Invalid IP address: %s", ip_str);
        close(sock);
        return -EINVAL;
    }

    if (ioctl(sock, SIOCSIFADDR, (void *)&ifr) < 0) {
        LOG_ERROR("tun_set_ip: ioctl(SIOCSIFADDR) failed: %s", strerror(errno));
        int err = -errno;
        close(sock);
        return err;
    }

    /* Set Netmask (SIOCSIFNETMASK ioctl) */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", tun->name);
    addr = (struct sockaddr_in *)(void *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask_str, &addr->sin_addr) <= 0) {
        LOG_ERROR("tun_set_ip: Invalid netmask: %s", netmask_str);
        close(sock);
        return -EINVAL;
    }

    if (ioctl(sock, SIOCSIFNETMASK, (void *)&ifr) < 0) {
        LOG_ERROR("tun_set_ip: ioctl(SIOCSIFNETMASK) failed: %s", strerror(errno));
        int err = -errno;
        close(sock);
        return err;
    }

    close(sock);
    LOG_INFO("tun_set_ip: Assigned %s / %s to %s", ip_str, netmask_str, tun->name);
    return 0;
#else
    (void)ip_str; (void)netmask_str;
    return -ENOSYS;
#endif
}

/* =========================================================================
 * tun_set_up
 *
 * Bring the TUN interface UP and RUNNING so the OS kernel routes packets to it.
 * Equivalent to running `ip link set dev vpn0 up`.
 * ========================================================================= */
int tun_set_up(const tun_device_t *tun) {
    if (!tun || tun->fd < 0) {
        LOG_ERROR("tun_set_up: Invalid TUN device");
        return -EINVAL;
    }

#ifdef __linux__
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR("tun_set_up: Failed to open control socket: %s", strerror(errno));
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", tun->name);

    if (ioctl(sock, SIOCGIFFLAGS, (void *)&ifr) < 0) {
        LOG_ERROR("tun_set_up: ioctl(SIOCGIFFLAGS) failed: %s", strerror(errno));
        int err = -errno;
        close(sock);
        return err;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(sock, SIOCSIFFLAGS, (void *)&ifr) < 0) {
        LOG_ERROR("tun_set_up: ioctl(SIOCSIFFLAGS) failed: %s", strerror(errno));
        int err = -errno;
        close(sock);
        return err;
    }

    close(sock);
    LOG_INFO("tun_set_up: Interface %s is UP and RUNNING", tun->name);
    return 0;
#else
    return -ENOSYS;
#endif
}

/* =========================================================================
 * tun_read
 *
 * Read a cleartext raw IP packet written to the TUN device by the OS kernel.
 *
 * RETURN:
 *   Bytes read (> 0), 0 if no packet waiting (EAGAIN), or negative errno on error.
 * ========================================================================= */
ssize_t tun_read(const tun_device_t *tun, uint8_t *buf, size_t buf_len) {
    if (!tun || tun->fd < 0 || !buf || buf_len == 0) {
        return -EINVAL;
    }

    ssize_t n = read(tun->fd, buf, buf_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0; /* Non-blocking read: no packet available */
        }
        LOG_ERROR("tun_read: Read error: %s", strerror(errno));
        return -errno;
    }

    return n;
}

/* =========================================================================
 * tun_write
 *
 * Write a decrypted raw IP packet into the TUN device so the kernel delivers
 * it to local network applications.
 * ========================================================================= */
ssize_t tun_write(const tun_device_t *tun, const uint8_t *buf, size_t buf_len) {
    if (!tun || tun->fd < 0 || !buf || buf_len == 0) {
        return -EINVAL;
    }

    if (buf_len > (size_t)tun->mtu) {
        LOG_WARN("tun_write: Packet size %zu exceeds MTU %d", buf_len, tun->mtu);
        return -EMSGSIZE;
    }

    ssize_t n = write(tun->fd, buf, buf_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0;
        }
        LOG_ERROR("tun_write: Write error: %s", strerror(errno));
        return -errno;
    }

    return n;
}

/* =========================================================================
 * tun_close
 *
 * Close TUN file descriptor and reset `fd` to -1.
 * ========================================================================= */
void tun_close(tun_device_t *tun) {
    if (tun && tun->fd >= 0) {
        LOG_INFO("tun_close: Closing TUN interface %s", tun->name);
        close(tun->fd);
        tun->fd = -1;
    }
}

