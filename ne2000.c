/*
 * QEMU NE2000 emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ne2000.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
//#include "hw.h"
//#include "pc.h"
//#include "net.h"

#ifndef BUILD_ESP32
#if defined(_WIN32)
#include <winsock2.h>
#endif
#if !defined(__wasm__)
//#define USE_TUNTAP
#define USE_SLIRP
#endif
#else
#include "esp_mac.h"
#endif

#ifdef BUILD_ESP32
void *pcmalloc(long size);
#else
#define pcmalloc malloc
#endif

static uint16_t le16_to_cpu(uint16_t x)
{
    return x;
}

static uint16_t cpu_to_le16(uint16_t x)
{
    return x;
}

/* debug NE2000 card */
//#define DEBUG_NE2000

#define MAX_ETH_FRAME_SIZE 1514

#define E8390_CMD	0x00  /* The command register (for all pages) */
/* Page 0 register offsets. */
#define EN0_CLDALO	0x01	/* Low byte of current local dma addr  RD */
#define EN0_STARTPG	0x01	/* Starting page of ring bfr WR */
#define EN0_CLDAHI	0x02	/* High byte of current local dma addr  RD */
#define EN0_STOPPG	0x02	/* Ending page +1 of ring bfr WR */
#define EN0_BOUNDARY	0x03	/* Boundary page of ring bfr RD WR */
#define EN0_TSR		0x04	/* Transmit status reg RD */
#define EN0_TPSR	0x04	/* Transmit starting page WR */
#define EN0_NCR		0x05	/* Number of collision reg RD */
#define EN0_TCNTLO	0x05	/* Low  byte of tx byte count WR */
#define EN0_FIFO	0x06	/* FIFO RD */
#define EN0_TCNTHI	0x06	/* High byte of tx byte count WR */
#define EN0_ISR		0x07	/* Interrupt status reg RD WR */
#define EN0_CRDALO	0x08	/* low byte of current remote dma address RD */
#define EN0_RSARLO	0x08	/* Remote start address reg 0 */
#define EN0_CRDAHI	0x09	/* high byte, current remote dma address RD */
#define EN0_RSARHI	0x09	/* Remote start address reg 1 */
#define EN0_RCNTLO	0x0a	/* Remote byte count reg WR */
#define EN0_RTL8029ID0	0x0a	/* Realtek ID byte #1 RD */
#define EN0_RCNTHI	0x0b	/* Remote byte count reg WR */
#define EN0_RTL8029ID1	0x0b	/* Realtek ID byte #2 RD */
#define EN0_RSR		0x0c	/* rx status reg RD */
#define EN0_RXCR	0x0c	/* RX configuration reg WR */
#define EN0_TXCR	0x0d	/* TX configuration reg WR */
#define EN0_COUNTER0	0x0d	/* Rcv alignment error counter RD */
#define EN0_DCFG	0x0e	/* Data configuration reg WR */
#define EN0_COUNTER1	0x0e	/* Rcv CRC error counter RD */
#define EN0_IMR		0x0f	/* Interrupt mask reg WR */
#define EN0_COUNTER2	0x0f	/* Rcv missed frame error counter RD */

#define EN1_PHYS        0x11
#define EN1_CURPAG      0x17
#define EN1_MULT        0x18

#define EN2_STARTPG	0x21	/* Starting page of ring bfr RD */
#define EN2_STOPPG	0x22	/* Ending page +1 of ring bfr RD */

#define EN3_CONFIG0	0x33
#define EN3_CONFIG1	0x34
#define EN3_CONFIG2	0x35
#define EN3_CONFIG3	0x36

/*  Register accessed at EN_CMD, the 8390 base addr.  */
#define E8390_STOP	0x01	/* Stop and reset the chip */
#define E8390_START	0x02	/* Start the chip, clear reset */
#define E8390_TRANS	0x04	/* Transmit a frame */
#define E8390_RREAD	0x08	/* Remote read */
#define E8390_RWRITE	0x10	/* Remote write  */
#define E8390_NODMA	0x20	/* Remote DMA */
#define E8390_PAGE0	0x00	/* Select page chip registers */
#define E8390_PAGE1	0x40	/* using the two high-order bits */
#define E8390_PAGE2	0x80	/* Page 3 is invalid. */

/* Bits in EN0_ISR - Interrupt status register */
#define ENISR_RX	0x01	/* Receiver, no error */
#define ENISR_TX	0x02	/* Transmitter, no error */
#define ENISR_RX_ERR	0x04	/* Receiver, with error */
#define ENISR_TX_ERR	0x08	/* Transmitter, with error */
#define ENISR_OVER	0x10	/* Receiver overwrote the ring */
#define ENISR_COUNTERS	0x20	/* Counters need emptying */
#define ENISR_RDC	0x40	/* remote dma complete */
#define ENISR_RESET	0x80	/* Reset completed */
#define ENISR_ALL	0x3f	/* Interrupts we will enable */

/* Bits in received packet status byte and EN0_RSR*/
#define ENRSR_RXOK	0x01	/* Received a good packet */
#define ENRSR_CRC	0x02	/* CRC error */
#define ENRSR_FAE	0x04	/* frame alignment error */
#define ENRSR_FO	0x08	/* FIFO overrun */
#define ENRSR_MPA	0x10	/* missed pkt */
#define ENRSR_PHY	0x20	/* physical/multicast address */
#define ENRSR_DIS	0x40	/* receiver disable. set in monitor mode */
#define ENRSR_DEF	0x80	/* deferring */

/* Transmitted packet status, EN0_TSR. */
#define ENTSR_PTX 0x01	/* Packet transmitted without error */
#define ENTSR_ND  0x02	/* The transmit wasn't deferred. */
#define ENTSR_COL 0x04	/* The transmit collided at least once. */
#define ENTSR_ABT 0x08  /* The transmit collided 16 times, and was deferred. */
#define ENTSR_CRS 0x10	/* The carrier sense was lost. */
#define ENTSR_FU  0x20  /* A "FIFO underrun" occurred during transmit. */
#define ENTSR_CDH 0x40	/* The collision detect "heartbeat" signal was lost. */
#define ENTSR_OWC 0x80  /* There was an out-of-window collision. */

#define NE2000_PMEM_SIZE    (32*1024)
#define NE2000_PMEM_START   (16*1024)
#define NE2000_PMEM_END     (NE2000_PMEM_SIZE+NE2000_PMEM_START)
#define NE2000_MEM_SIZE     NE2000_PMEM_END

struct NE2000State {
    uint8_t cmd;
    uint32_t start;
    uint32_t stop;
    uint8_t boundary;
    uint8_t tsr;
    uint8_t tpsr;
    uint16_t tcnt;
    uint16_t rcnt;
    uint32_t rsar;
    uint8_t rsr;
    uint8_t rxcr;
    _Atomic uint8_t isr;
    uint8_t dcfg;
    uint8_t imr;
    uint8_t phys[6]; /* mac address */
    uint8_t curpag;
    uint8_t mult[8]; /* multicast mask array */
    int irq;
    void *pic;
    void (*set_irq)(void *pic, int irq, int level);
    int isa_io_base;
    void *vc;
    uint8_t macaddr[6];
    uint8_t mem[NE2000_MEM_SIZE];
};

static void ne2000_reset(NE2000State *s)
{
    int i;

    atomic_store_explicit(&(s->isr), ENISR_RESET, memory_order_relaxed);
    memcpy(s->mem, s->macaddr, 6);
    s->mem[14] = 0x57;
    s->mem[15] = 0x57;

    /* duplicate prom data */
    for(i = 15;i >= 0; i--) {
        s->mem[2 * i] = s->mem[i];
        s->mem[2 * i + 1] = s->mem[i];
    }
}

static void ne2000_update_irq(NE2000State *s)
{
    int isr, sisr;
    sisr = atomic_load_explicit(&(s->isr), memory_order_relaxed);
    isr = (sisr & s->imr) & 0x7f;
#if defined(DEBUG_NE2000)
    printf("NE2000: Set IRQ to %d (%02x %02x)\n",
	   isr ? 1 : 0, sisr, s->imr);
#endif
    s->set_irq(s->pic, s->irq, (isr != 0));
}

#define POLYNOMIAL 0x04c11db6

/* From FreeBSD */
/* XXX: optimize */
static int compute_mcast_idx(const uint8_t *ep)
{
    uint32_t crc;
    int carry, i, j;
    uint8_t b;

    crc = 0xffffffff;
    for (i = 0; i < 6; i++) {
        b = *ep++;
        for (j = 0; j < 8; j++) {
            carry = ((crc & 0x80000000L) ? 1 : 0) ^ (b & 0x01);
            crc <<= 1;
            b >>= 1;
            if (carry)
                crc = ((crc ^ POLYNOMIAL) | carry);
        }
    }
    return (crc >> 26);
}

static int ne2000_buffer_full(NE2000State *s)
{
    int avail, index, boundary;

    index = s->curpag << 8;
    boundary = s->boundary << 8;
    if (index < boundary)
        avail = boundary - index;
    else
        avail = (s->stop - s->start) - (index - boundary);
    if (avail < (MAX_ETH_FRAME_SIZE + 4))
        return 1;
    return 0;
}

static int ne2000_can_receive(void *opaque)
{
    NE2000State *s = opaque;

    if (s->cmd & E8390_STOP)
        return 1;
    return !ne2000_buffer_full(s);
}

#define MIN_BUF_SIZE 60

static void ne2000_receive(void *opaque, const uint8_t *buf, int size)
{
    NE2000State *s = opaque;
    uint8_t *p;
    unsigned int total_len, next, avail, len, index, mcast_idx;
    uint8_t buf1[60];
    static const uint8_t broadcast_macaddr[6] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#if defined(DEBUG_NE2000)
    printf("NE2000: received len=%d\n", size);
#endif

    if (s->cmd & E8390_STOP || ne2000_buffer_full(s))
        return;

    /* XXX: check this */
    if (s->rxcr & 0x10) {
        /* promiscuous: receive all */
    } else {
        if (!memcmp(buf,  broadcast_macaddr, 6)) {
            /* broadcast address */
            if (!(s->rxcr & 0x04))
                return;
        } else if (buf[0] & 0x01) {
            /* multicast */
            if (!(s->rxcr & 0x08))
                return;
            mcast_idx = compute_mcast_idx(buf);
            if (!(s->mult[mcast_idx >> 3] & (1 << (mcast_idx & 7))))
                return;
        } else if (s->mem[0] == buf[0] &&
                   s->mem[2] == buf[1] &&
                   s->mem[4] == buf[2] &&
                   s->mem[6] == buf[3] &&
                   s->mem[8] == buf[4] &&
                   s->mem[10] == buf[5]) {
            /* match */
        } else {
            return;
        }
    }


    /* if too small buffer, then expand it */
    if (size < MIN_BUF_SIZE) {
        memcpy(buf1, buf, size);
        memset(buf1 + size, 0, MIN_BUF_SIZE - size);
        buf = buf1;
        size = MIN_BUF_SIZE;
    }

    index = s->curpag << 8;
    /* 4 bytes for header */
    total_len = size + 4;
    /* address for next packet (4 bytes for CRC) */
    next = index + ((total_len + 4 + 255) & ~0xff);
    if (next >= s->stop)
        next -= (s->stop - s->start);
    /* prepare packet header */
    p = s->mem + index;
    s->rsr = ENRSR_RXOK; /* receive status */
    /* XXX: check this */
    if (buf[0] & 0x01)
        s->rsr |= ENRSR_PHY;
    p[0] = s->rsr;
    p[1] = next >> 8;
    p[2] = total_len;
    p[3] = total_len >> 8;
    index += 4;

    /* write packet data */
    while (size > 0) {
        if (index <= s->stop)
            avail = s->stop - index;
        else
            avail = 0;
        len = size;
        if (len > avail)
            len = avail;
        memcpy(s->mem + index, buf, len);
        buf += len;
        index += len;
        if (index == s->stop)
            index = s->start;
        size -= len;
    }
    s->curpag = next >> 8;

    /* now we can signal we have received something */
    atomic_fetch_or_explicit(&(s->isr), ENISR_RX, memory_order_release);
#ifndef BUILD_ESP32
    ne2000_update_irq(s);
#endif
}

#if defined(USE_TUNTAP)
struct TUN {
    int fd;
};

static void qemu_send_packet(void *vc, uint8_t *buf, int size)
{
    struct TUN *tun = vc;
    if (tun->fd < 0)
        return;
    write(tun->fd, buf, size);
}

void ne2000_step(NE2000State *s)
{
    struct TUN *tun = s->vc;
    uint8_t buf[2048];

    if (tun->fd < 0)
        return;
    while (ne2000_can_receive(s)) {
        int ret = read(tun->fd, buf, sizeof(buf));
        if (ret <= 0)
            break;
        ne2000_receive(s, buf, ret);
    }
}

static void *net_open(NE2000State *s)
{
    struct TUN *tun = malloc(sizeof(struct TUN));
    tun->fd = -1;
    if (getenv("TAPFD"))
        tun->fd = atoi(getenv("TAPFD"));
    if (tun->fd >= 0)
        fcntl(tun->fd, F_SETFL, O_NONBLOCK);
    return tun;
}

#elif defined(USE_SLIRP)
#include <slirp/libslirp.h>
#include <stdio.h>
struct SLIRP {
    void *slirp;
    void *ne2000;
    uint32_t nextts;
    fd_set rfds, wfds, efds;
    unsigned int maxfd;
};

static void qemu_send_packet(void *vc, uint8_t *buf, int size)
{
    struct SLIRP *s = vc;
    slirp_input(s->slirp, buf, size);
}

int slirp_can_output(void *opaque)
{
    struct SLIRP *s = opaque;
    return ne2000_can_receive(s->ne2000);
}

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len)
{
    struct SLIRP *s = opaque;
    ne2000_receive(s->ne2000, pkt, pkt_len);
}

uint32_t get_uticks();


static slirp_ssize_t cb_send_packet(const void *buf, size_t len, void *opaque)
{
    if (slirp_can_output(opaque)) {
        slirp_output(opaque, buf, len);
        return len;
    }
    return 0;
}

static void cb_guest_error(const char *msg, void *opaque)
{
    fprintf(stderr, "slirp: guest error: %s\n", msg);
}

static int64_t cb_clock_get_ns(void *opaque)
{
    return ((int64_t) get_uticks()) * 1000; // XXX: wrap
}

static void *cb_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    fprintf(stderr, "slirp: TODO: timer_new\n");
    return NULL;
}

static void cb_timer_free(void *_timer, void *opaque)
{
}

static void cb_timer_mod(void *timer, int64_t expire_time, void *opaque)
{
    fprintf(stderr, "slirp: TODO: timer_mod\n");
}

static void cb_register_poll_fd(int fd, void *opaque)
{
}

static void cb_unregister_poll_fd(int fd, void *opaque)
{
}

static void cb_notify(void *opaque)
{
}

static const SlirpCb cb = {
    .send_packet = cb_send_packet,
    .guest_error = cb_guest_error,
    .clock_get_ns = cb_clock_get_ns,
    .timer_new = cb_timer_new,
    .timer_free = cb_timer_free,
    .timer_mod = cb_timer_mod,
    .register_poll_fd = cb_register_poll_fd,
    .unregister_poll_fd = cb_unregister_poll_fd,
    .notify = cb_notify,
};

#if SLIRP_CONFIG_VERSION_MAX < 6
typedef int slirp_os_socket;
#define slirp_pollfds_fill_socket slirp_pollfds_fill
#endif
static int add_poll_cb(slirp_os_socket fd, int events, void *opaque)
{
    struct SLIRP *slirp = opaque;
    if (events & SLIRP_POLL_IN)
        FD_SET(fd, &slirp->rfds);
    if (events & SLIRP_POLL_OUT)
        FD_SET(fd, &slirp->wfds);
    if (events & SLIRP_POLL_PRI)
        FD_SET(fd, &slirp->efds);
    if (slirp->maxfd < fd)
        slirp->maxfd = fd;
    return fd;
}

static int get_revents_cb(int idx, void *opaque)
{
    struct SLIRP *slirp = opaque;
    int event = 0;
    if (FD_ISSET(idx, &slirp->rfds))
        event |= SLIRP_POLL_IN;
    if (FD_ISSET(idx, &slirp->wfds))
        event |= SLIRP_POLL_OUT;
    if (FD_ISSET(idx, &slirp->efds))
        event |= SLIRP_POLL_PRI;
    return event;
}

void ne2000_step(NE2000State *ne2000)
{
    struct SLIRP *s = ne2000->vc;
    uint32_t now = get_uticks();
    if (now < s->nextts)
        return;
    s->nextts = now + 10000;

    /* wait for an event */
    FD_ZERO(&s->rfds);
    FD_ZERO(&s->wfds);
    FD_ZERO(&s->efds);
    s->maxfd = 0;

    int _ = 0;
    slirp_pollfds_fill_socket(s->slirp, &_, add_poll_cb, s);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int ret = select(s->maxfd+1, &s->rfds, &s->wfds, &s->efds, &tv);
    slirp_pollfds_poll(s->slirp, ret < 0, get_revents_cb, s);
}

static void *net_open(NE2000State *s)
{
    struct in_addr net_addr  = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */
    struct in_addr dns  = { .s_addr = htonl(0x0a000203) }; /* 10.0.2.3 */
    const char *bootfile = NULL;
    const char *vhostname = NULL;
    int restricted = 0;

    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;
    cfg.restricted = restricted;
    cfg.in_enabled = true;
    cfg.vnetwork = net_addr;
    cfg.vnetmask = mask;
    cfg.vhost = host;
    cfg.in6_enabled = false;
    cfg.vhostname = vhostname;
    cfg.bootfile = bootfile;
    cfg.vdhcp_start = dhcp;
    cfg.vnameserver = dns;

    struct SLIRP *slirp = malloc(sizeof(struct SLIRP));
    slirp->slirp = slirp_new(&cfg, &cb, slirp);
    slirp->ne2000 = s;
    slirp->nextts = get_uticks();
    return slirp;
}

#else

#ifdef BUILD_ESP32
extern void (*_Atomic esp32_send_packet)(uint8_t *buf, int size);
static void qemu_send_packet(void *vc, uint8_t *buf, int size)
{
    void (*send_packet)(uint8_t *buf, int size);
    send_packet = atomic_load_explicit(&esp32_send_packet,
                                       memory_order_relaxed);
    if (send_packet)
        send_packet(buf, size);
}
#else
#include <stdio.h>
static void qemu_send_packet(void *vc, uint8_t *buf, int size)
{
    fprintf(stderr, "recv packet %d bytes:\n", size);
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");
}
#endif

void ne2000_step(NE2000State *s)
{
#ifdef BUILD_ESP32
    ne2000_update_irq(s);
#endif
}

static void *net_open(NE2000State *s)
{
    return NULL;
}

#endif

void ne2000_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    NE2000State *s = opaque;
    int offset, page, index;

    addr &= 0xf;
#ifdef DEBUG_NE2000
    printf("NE2000: write addr=0x%x val=0x%02x\n", addr, val);
#endif
    if (addr == E8390_CMD) {
        /* control register */
        s->cmd = val;
        if (!(val & E8390_STOP)) { /* START bit makes no sense on RTL8029... */
            atomic_fetch_and_explicit(&(s->isr), ~ENISR_RESET, memory_order_relaxed);
            /* test specific case: zero length transfer */
            if ((val & (E8390_RREAD | E8390_RWRITE)) &&
                s->rcnt == 0) {
                atomic_fetch_or_explicit(&(s->isr), ENISR_RDC, memory_order_release);
                ne2000_update_irq(s);
            }
            if (val & E8390_TRANS) {
                index = (s->tpsr << 8);
                /* XXX: next 2 lines are a hack to make netware 3.11 work */
                if (index >= NE2000_PMEM_END)
                    index -= NE2000_PMEM_SIZE;
                /* fail safe: check range on the transmitted length  */
                if (index + s->tcnt <= NE2000_PMEM_END) {
                    qemu_send_packet(s->vc, s->mem + index, s->tcnt);
                }
                /* signal end of transfer */
                s->tsr = ENTSR_PTX;
                atomic_fetch_or_explicit(&(s->isr), ENISR_TX, memory_order_release);
                s->cmd &= ~E8390_TRANS;
                ne2000_update_irq(s);
            }
        }
    } else {
        page = s->cmd >> 6;
        offset = addr | (page << 4);
        switch(offset) {
        case EN0_STARTPG:
            s->start = val << 8;
            break;
        case EN0_STOPPG:
            s->stop = val << 8;
            break;
        case EN0_BOUNDARY:
            s->boundary = val;
            break;
        case EN0_IMR:
            s->imr = val;
            ne2000_update_irq(s);
            break;
        case EN0_TPSR:
            s->tpsr = val;
            break;
        case EN0_TCNTLO:
            s->tcnt = (s->tcnt & 0xff00) | val;
            break;
        case EN0_TCNTHI:
            s->tcnt = (s->tcnt & 0x00ff) | (val << 8);
            break;
        case EN0_RSARLO:
            s->rsar = (s->rsar & 0xff00) | val;
            break;
        case EN0_RSARHI:
            s->rsar = (s->rsar & 0x00ff) | (val << 8);
            break;
        case EN0_RCNTLO:
            s->rcnt = (s->rcnt & 0xff00) | val;
            break;
        case EN0_RCNTHI:
            s->rcnt = (s->rcnt & 0x00ff) | (val << 8);
            break;
        case EN0_RXCR:
            s->rxcr = val;
            break;
        case EN0_DCFG:
            s->dcfg = val;
            break;
        case EN0_ISR:
            atomic_fetch_and_explicit(&(s->isr), ~(val & 0x7f), memory_order_relaxed);
            ne2000_update_irq(s);
            break;
        case EN1_PHYS ... EN1_PHYS + 5:
            s->phys[offset - EN1_PHYS] = val;
            break;
        case EN1_CURPAG:
            s->curpag = val;
            break;
        case EN1_MULT ... EN1_MULT + 7:
            s->mult[offset - EN1_MULT] = val;
            break;
        }
    }
}

uint32_t ne2000_ioport_read(void *opaque, uint32_t addr)
{
    NE2000State *s = opaque;
    int offset, page, ret;

    addr &= 0xf;
    if (addr == E8390_CMD) {
        ret = s->cmd;
    } else {
        page = s->cmd >> 6;
        offset = addr | (page << 4);
        switch(offset) {
        case EN0_TSR:
            ret = s->tsr;
            break;
        case EN0_BOUNDARY:
            ret = s->boundary;
            break;
        case EN0_ISR:
            ret = atomic_load_explicit(&(s->isr), memory_order_acquire);
            break;
	case EN0_RSARLO:
	    ret = s->rsar & 0x00ff;
	    break;
	case EN0_RSARHI:
	    ret = s->rsar >> 8;
	    break;
        case EN1_PHYS ... EN1_PHYS + 5:
            ret = s->phys[offset - EN1_PHYS];
            break;
        case EN1_CURPAG:
            ret = s->curpag;
            break;
        case EN1_MULT ... EN1_MULT + 7:
            ret = s->mult[offset - EN1_MULT];
            break;
        case EN0_RSR:
            ret = s->rsr;
            break;
        case EN2_STARTPG:
            ret = s->start >> 8;
            break;
        case EN2_STOPPG:
            ret = s->stop >> 8;
            break;
	case EN0_RTL8029ID0:
	    ret = 0x50;
	    break;
	case EN0_RTL8029ID1:
	    ret = 0x43;
	    break;
	case EN3_CONFIG0:
	    ret = 0;		/* 10baseT media */
	    break;
	case EN3_CONFIG2:
	    ret = 0x40;		/* 10baseT active */
	    break;
	case EN3_CONFIG3:
	    ret = 0x40;		/* Full duplex */
	    break;
        default:
            ret = 0x00;
            break;
        }
    }
#ifdef DEBUG_NE2000
    printf("NE2000: read addr=0x%x val=%02x\n", addr, ret);
#endif
    return ret;
}

static inline void ne2000_mem_writeb(NE2000State *s, uint32_t addr,
                                     uint32_t val)
{
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        s->mem[addr] = val;
    }
}

static inline void ne2000_mem_writew(NE2000State *s, uint32_t addr,
                                     uint32_t val)
{
    addr &= ~1; /* XXX: check exact behaviour if not even */
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        *(uint16_t *)(s->mem + addr) = cpu_to_le16(val);
    }
}

#if 0
static inline void ne2000_mem_writel(NE2000State *s, uint32_t addr,
                                     uint32_t val)
{
    addr &= ~1; /* XXX: check exact behaviour if not even */
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        cpu_to_le32wu((uint32_t *)(s->mem + addr), val);
    }
}
#endif

static inline uint32_t ne2000_mem_readb(NE2000State *s, uint32_t addr)
{
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        return s->mem[addr];
    } else {
        return 0xff;
    }
}

static inline uint32_t ne2000_mem_readw(NE2000State *s, uint32_t addr)
{
    addr &= ~1; /* XXX: check exact behaviour if not even */
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        return le16_to_cpu(*(uint16_t *)(s->mem + addr));
    } else {
        return 0xffff;
    }
}

#if 0
static inline uint32_t ne2000_mem_readl(NE2000State *s, uint32_t addr)
{
    addr &= ~1; /* XXX: check exact behaviour if not even */
    if (addr < 32 ||
        (addr >= NE2000_PMEM_START && addr < NE2000_MEM_SIZE)) {
        return le32_to_cpupu((uint32_t *)(s->mem + addr));
    } else {
        return 0xffffffff;
    }
}
#endif

static inline void ne2000_dma_update(NE2000State *s, int len)
{
    s->rsar += len;
    /* wrap */
    /* XXX: check what to do if rsar > stop */
    if (s->rsar == s->stop)
        s->rsar = s->start;

    if (s->rcnt <= len) {
        s->rcnt = 0;
        /* signal end of transfer */
        atomic_fetch_or_explicit(&(s->isr), ENISR_RDC, memory_order_release);
        ne2000_update_irq(s);
    } else {
        s->rcnt -= len;
    }
}

void ne2000_asic_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    NE2000State *s = opaque;

#ifdef DEBUG_NE2000
    printf("NE2000: asic write val=0x%04x\n", val);
#endif
    if (s->rcnt == 0)
        return;
    if (s->dcfg & 0x01) {
        /* 16 bit access */
        ne2000_mem_writew(s, s->rsar, val);
        ne2000_dma_update(s, 2);
    } else {
        /* 8 bit access */
        ne2000_mem_writeb(s, s->rsar, val);
        ne2000_dma_update(s, 1);
    }
}

uint32_t ne2000_asic_ioport_read(void *opaque, uint32_t addr)
{
    NE2000State *s = opaque;
    int ret;

    if (s->dcfg & 0x01) {
        /* 16 bit access */
        ret = ne2000_mem_readw(s, s->rsar);
        ne2000_dma_update(s, 2);
    } else {
        /* 8 bit access */
        ret = ne2000_mem_readb(s, s->rsar);
        ne2000_dma_update(s, 1);
    }
#ifdef DEBUG_NE2000
    printf("NE2000: asic read val=0x%04x\n", ret);
#endif
    return ret;
}

#if 0
static void ne2000_asic_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    NE2000State *s = opaque;

#ifdef DEBUG_NE2000
    printf("NE2000: asic writel val=0x%04x\n", val);
#endif
    if (s->rcnt == 0)
        return;
    /* 32 bit access */
    ne2000_mem_writel(s, s->rsar, val);
    ne2000_dma_update(s, 4);
}

static uint32_t ne2000_asic_ioport_readl(void *opaque, uint32_t addr)
{
    NE2000State *s = opaque;
    int ret;

    /* 32 bit access */
    ret = ne2000_mem_readl(s, s->rsar);
    ne2000_dma_update(s, 4);
#ifdef DEBUG_NE2000
    printf("NE2000: asic readl val=0x%04x\n", ret);
#endif
    return ret;
}
#endif

void ne2000_reset_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    /* nothing to do (end of reset pulse) */
}

uint32_t ne2000_reset_ioport_read(void *opaque, uint32_t addr)
{
    NE2000State *s = opaque;
    ne2000_reset(s);
    return 0;
}

typedef struct NICInfo {
    uint8_t macaddr[6];
    const char *model;
    const char *name;
//    VLANState *vlan;
//    VLANClientState *vc;
    void *private;
    int used;
} NICInfo;

#ifdef BUILD_ESP32
void *thene2000;

static inline int filter(uint8_t *buf, int size)
{
    if (size >= 38) {
        int l2type = (buf[12] << 8) | buf[13];
        switch(l2type) {
        case 0x0800: // ipv4
            switch (buf[23]) {
            case 0x06: // tcp
                if (buf[36] == 0x27 && buf[37] == 0x0f) { // dst 9999
                    return 0;
                } else {
                    return 1;
                }
            case 0x11: // udp
                if (buf[36] == 0x00 && buf[37] == 0x44) { // dhcp
                    return 2;
                } else {
                    return 1;
                }
            default:
                return 1;
            }
        case 0x0806: //arp
            return 2;
        default:
            return 0;
        }
    }
    return 0;
}

int wlanif_l2_input_hook(uint8_t *buf, int size)
{
    int r = filter(buf, size);
    if (r) {
        if (thene2000)
            ne2000_receive(thene2000, buf, size);
        if (r != 1)
            return 0;
        return 1;
    }
    return 0;
}
#endif

NE2000State *isa_ne2000_init(int base, int irq,
                             void *pic,
                             void (*set_irq)(void *pic, int irq, int level))
{
    NE2000State *s;

    s = pcmalloc(sizeof(NE2000State));
    memset(s, 0, sizeof(NE2000State));
    atomic_init(&(s->isr), 0);
    s->vc = net_open(s);

#if 0
    register_ioport_write(base, 16, 1, ne2000_ioport_write, s);
    register_ioport_read(base, 16, 1, ne2000_ioport_read, s);

    register_ioport_write(base + 0x10, 1, 1, ne2000_asic_ioport_write, s);
    register_ioport_read(base + 0x10, 1, 1, ne2000_asic_ioport_read, s);
    register_ioport_write(base + 0x10, 2, 2, ne2000_asic_ioport_write, s);
    register_ioport_read(base + 0x10, 2, 2, ne2000_asic_ioport_read, s);

    register_ioport_write(base + 0x1f, 1, 1, ne2000_reset_ioport_write, s);
    register_ioport_read(base + 0x1f, 1, 1, ne2000_reset_ioport_read, s);
#endif
    s->isa_io_base = base;
    s->irq = irq;
    s->pic = pic;
    s->set_irq = set_irq;
#ifndef BUILD_ESP32
    const static uint8_t macaddr[6] = {0x52, 0x54, 0x00, 0x78, 0x9a, 0xbc};
    memcpy(s->macaddr, macaddr, 6);
#else
    esp_read_mac(s->macaddr, ESP_MAC_WIFI_STA);
    thene2000 = s;
#endif

    ne2000_reset(s);

//    s->vc = nd->vc = qemu_new_vlan_client(nd->vlan, nd->model, nd->name,
//                                          ne2000_receive, ne2000_can_receive,
//                                          isa_ne2000_cleanup, s);

//    qemu_format_nic_info_str(s->vc, s->macaddr);
    return s;
}
