/*
 * IDE emulation
 * 
 * Copyright (c) 2003-2016 Fabrice Bellard
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

//#include "cutils.h"
#include "ide.h"

//#define DEBUG_IDE
//#define DEBUG_IDE_ATAPI

/* Bits of HD_STATUS */
#define ERR_STAT		0x01
#define INDEX_STAT		0x02
#define ECC_STAT		0x04	/* Corrected error */
#define DRQ_STAT		0x08
#define SEEK_STAT		0x10
#define SRV_STAT		0x10
#define WRERR_STAT		0x20
#define READY_STAT		0x40
#define BUSY_STAT		0x80

/* Bits for HD_ERROR */
#define MARK_ERR		0x01	/* Bad address mark */
#define TRK0_ERR		0x02	/* couldn't find track 0 */
#define ABRT_ERR		0x04	/* Command aborted */
#define MCR_ERR			0x08	/* media change request */
#define ID_ERR			0x10	/* ID field not found */
#define MC_ERR			0x20	/* media changed */
#define ECC_ERR			0x40	/* Uncorrectable ECC error */
#define BBD_ERR			0x80	/* pre-EIDE meaning:  block marked bad */
#define ICRC_ERR		0x80	/* new meaning:  CRC error during transfer */

/* Bits of HD_NSECTOR */
#define CD			0x01
#define IO			0x02
#define REL			0x04
#define TAG_MASK		0xf8

#define IDE_CMD_RESET           0x04
#define IDE_CMD_DISABLE_IRQ     0x02

/* ATA/ATAPI Commands pre T13 Spec */
#define WIN_NOP				0x00
/*
 *	0x01->0x02 Reserved
 */
#define CFA_REQ_EXT_ERROR_CODE		0x03 /* CFA Request Extended Error Code */
/*
 *	0x04->0x07 Reserved
 */
#define WIN_SRST			0x08 /* ATAPI soft reset command */
#define WIN_DEVICE_RESET		0x08
/*
 *	0x09->0x0F Reserved
 */
#define WIN_RECAL			0x10
#define WIN_RESTORE			WIN_RECAL
/*
 *	0x10->0x1F Reserved
 */
#define WIN_READ			0x20 /* 28-Bit */
#define WIN_READ_ONCE			0x21 /* 28-Bit without retries */
#define WIN_READ_LONG			0x22 /* 28-Bit */
#define WIN_READ_LONG_ONCE		0x23 /* 28-Bit without retries */
#define WIN_READ_EXT			0x24 /* 48-Bit */
#define WIN_READDMA_EXT			0x25 /* 48-Bit */
#define WIN_READDMA_QUEUED_EXT		0x26 /* 48-Bit */
#define WIN_READ_NATIVE_MAX_EXT		0x27 /* 48-Bit */
/*
 *	0x28
 */
#define WIN_MULTREAD_EXT		0x29 /* 48-Bit */
/*
 *	0x2A->0x2F Reserved
 */
#define WIN_WRITE			0x30 /* 28-Bit */
#define WIN_WRITE_ONCE			0x31 /* 28-Bit without retries */
#define WIN_WRITE_LONG			0x32 /* 28-Bit */
#define WIN_WRITE_LONG_ONCE		0x33 /* 28-Bit without retries */
#define WIN_WRITE_EXT			0x34 /* 48-Bit */
#define WIN_WRITEDMA_EXT		0x35 /* 48-Bit */
#define WIN_WRITEDMA_QUEUED_EXT		0x36 /* 48-Bit */
#define WIN_SET_MAX_EXT			0x37 /* 48-Bit */
#define CFA_WRITE_SECT_WO_ERASE		0x38 /* CFA Write Sectors without erase */
#define WIN_MULTWRITE_EXT		0x39 /* 48-Bit */
/*
 *	0x3A->0x3B Reserved
 */
#define WIN_WRITE_VERIFY		0x3C /* 28-Bit */
/*
 *	0x3D->0x3F Reserved
 */
#define WIN_VERIFY			0x40 /* 28-Bit - Read Verify Sectors */
#define WIN_VERIFY_ONCE			0x41 /* 28-Bit - without retries */
#define WIN_VERIFY_EXT			0x42 /* 48-Bit */
/*
 *	0x43->0x4F Reserved
 */
#define WIN_FORMAT			0x50
/*
 *	0x51->0x5F Reserved
 */
#define WIN_INIT			0x60
/*
 *	0x61->0x5F Reserved
 */
#define WIN_SEEK			0x70 /* 0x70-0x7F Reserved */
#define CFA_TRANSLATE_SECTOR		0x87 /* CFA Translate Sector */
#define WIN_DIAGNOSE			0x90
#define WIN_SPECIFY			0x91 /* set drive geometry translation */
#define WIN_DOWNLOAD_MICROCODE		0x92
#define WIN_STANDBYNOW2			0x94
#define WIN_STANDBY2			0x96
#define WIN_SETIDLE2			0x97
#define WIN_CHECKPOWERMODE2		0x98
#define WIN_SLEEPNOW2			0x99
/*
 *	0x9A VENDOR
 */
#define WIN_PACKETCMD			0xA0 /* Send a packet command. */
#define WIN_PIDENTIFY			0xA1 /* identify ATAPI device	*/
#define WIN_QUEUED_SERVICE		0xA2
#define WIN_SMART			0xB0 /* self-monitoring and reporting */
#define CFA_ERASE_SECTORS       	0xC0
#define WIN_MULTREAD			0xC4 /* read sectors using multiple mode*/
#define WIN_MULTWRITE			0xC5 /* write sectors using multiple mode */
#define WIN_SETMULT			0xC6 /* enable/disable multiple mode */
#define WIN_READDMA_QUEUED		0xC7 /* read sectors using Queued DMA transfers */
#define WIN_READDMA			0xC8 /* read sectors using DMA transfers */
#define WIN_READDMA_ONCE		0xC9 /* 28-Bit - without retries */
#define WIN_WRITEDMA			0xCA /* write sectors using DMA transfers */
#define WIN_WRITEDMA_ONCE		0xCB /* 28-Bit - without retries */
#define WIN_WRITEDMA_QUEUED		0xCC /* write sectors using Queued DMA transfers */
#define CFA_WRITE_MULTI_WO_ERASE	0xCD /* CFA Write multiple without erase */
#define WIN_GETMEDIASTATUS		0xDA	
#define WIN_ACKMEDIACHANGE		0xDB /* ATA-1, ATA-2 vendor */
#define WIN_POSTBOOT			0xDC
#define WIN_PREBOOT			0xDD
#define WIN_DOORLOCK			0xDE /* lock door on removable drives */
#define WIN_DOORUNLOCK			0xDF /* unlock door on removable drives */
#define WIN_STANDBYNOW1			0xE0
#define WIN_IDLEIMMEDIATE		0xE1 /* force drive to become "ready" */
#define WIN_STANDBY             	0xE2 /* Set device in Standby Mode */
#define WIN_SETIDLE1			0xE3
#define WIN_READ_BUFFER			0xE4 /* force read only 1 sector */
#define WIN_CHECKPOWERMODE1		0xE5
#define WIN_SLEEPNOW1			0xE6
#define WIN_FLUSH_CACHE			0xE7
#define WIN_WRITE_BUFFER		0xE8 /* force write only 1 sector */
#define WIN_WRITE_SAME			0xE9 /* read ata-2 to use */
	/* SET_FEATURES 0x22 or 0xDD */
#define WIN_FLUSH_CACHE_EXT		0xEA /* 48-Bit */
#define WIN_IDENTIFY			0xEC /* ask drive to identify itself	*/
#define WIN_MEDIAEJECT			0xED
#define WIN_IDENTIFY_DMA		0xEE /* same as WIN_IDENTIFY, but DMA */
#define WIN_SETFEATURES			0xEF /* set special drive features */
#define EXABYTE_ENABLE_NEST		0xF0
#define WIN_SECURITY_SET_PASS		0xF1
#define WIN_SECURITY_UNLOCK		0xF2
#define WIN_SECURITY_ERASE_PREPARE	0xF3
#define WIN_SECURITY_ERASE_UNIT		0xF4
#define WIN_SECURITY_FREEZE_LOCK	0xF5
#define WIN_SECURITY_DISABLE		0xF6
#define WIN_READ_NATIVE_MAX		0xF8 /* return the native maximum address */
#define WIN_SET_MAX			0xF9
#define DISABLE_SEAGATE			0xFB

/* ATAPI defines */

#define ATAPI_PACKET_SIZE 12

/* The generic packet command opcodes for CD/DVD Logical Units,
 * From Table 57 of the SFF8090 Ver. 3 (Mt. Fuji) draft standard. */
#define GPCMD_BLANK			    0xa1
#define GPCMD_CLOSE_TRACK		    0x5b
#define GPCMD_FLUSH_CACHE		    0x35
#define GPCMD_FORMAT_UNIT		    0x04
#define GPCMD_GET_CONFIGURATION		    0x46
#define GPCMD_GET_EVENT_STATUS_NOTIFICATION 0x4a
#define GPCMD_GET_PERFORMANCE		    0xac
#define GPCMD_INQUIRY			    0x12
#define GPCMD_LOAD_UNLOAD		    0xa6
#define GPCMD_MECHANISM_STATUS		    0xbd
#define GPCMD_MODE_SELECT_10		    0x55
#define GPCMD_MODE_SENSE_10		    0x5a
#define GPCMD_PAUSE_RESUME		    0x4b
#define GPCMD_PLAY_AUDIO_10		    0x45
#define GPCMD_PLAY_AUDIO_MSF		    0x47
#define GPCMD_PLAY_AUDIO_TI		    0x48
#define GPCMD_PLAY_CD			    0xbc
#define GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL  0x1e
#define GPCMD_READ_10			    0x28
#define GPCMD_READ_12			    0xa8
#define GPCMD_READ_CDVD_CAPACITY	    0x25
#define GPCMD_READ_CD			    0xbe
#define GPCMD_READ_CD_MSF		    0xb9
#define GPCMD_READ_DISC_INFO		    0x51
#define GPCMD_READ_DVD_STRUCTURE	    0xad
#define GPCMD_READ_FORMAT_CAPACITIES	    0x23
#define GPCMD_READ_HEADER		    0x44
#define GPCMD_READ_TRACK_RZONE_INFO	    0x52
#define GPCMD_READ_SUBCHANNEL		    0x42
#define GPCMD_READ_TOC_PMA_ATIP		    0x43
#define GPCMD_REPAIR_RZONE_TRACK	    0x58
#define GPCMD_REPORT_KEY		    0xa4
#define GPCMD_REQUEST_SENSE		    0x03
#define GPCMD_RESERVE_RZONE_TRACK	    0x53
#define GPCMD_SCAN			    0xba
#define GPCMD_SEEK			    0x2b
#define GPCMD_SEND_DVD_STRUCTURE	    0xad
#define GPCMD_SEND_EVENT		    0xa2
#define GPCMD_SEND_KEY			    0xa3
#define GPCMD_SEND_OPC			    0x54
#define GPCMD_SET_READ_AHEAD		    0xa7
#define GPCMD_SET_STREAMING		    0xb6
#define GPCMD_START_STOP_UNIT		    0x1b
#define GPCMD_STOP_PLAY_SCAN		    0x4e
#define GPCMD_TEST_UNIT_READY		    0x00
#define GPCMD_VERIFY_10			    0x2f
#define GPCMD_WRITE_10			    0x2a
#define GPCMD_WRITE_AND_VERIFY_10	    0x2e
/* This is listed as optional in ATAPI 2.6, but is (curiously)
 * missing from Mt. Fuji, Table 57.  It _is_ mentioned in Mt. Fuji
 * Table 377 as an MMC command for SCSi devices though...  Most ATAPI
 * drives support it. */
#define GPCMD_SET_SPEED			    0xbb
/* This seems to be a SCSI specific CD-ROM opcode
 * to play data at track/index */
#define GPCMD_PLAYAUDIO_TI		    0x48
/*
 * From MS Media Status Notification Support Specification. For
 * older drives only.
 */
#define GPCMD_GET_MEDIA_STATUS		    0xda
#define GPCMD_MODE_SENSE_6		    0x1a

/* Mode page codes for mode sense/set */
#define GPMODE_R_W_ERROR_PAGE		0x01
#define GPMODE_WRITE_PARMS_PAGE		0x05
#define GPMODE_AUDIO_CTL_PAGE		0x0e
#define GPMODE_POWER_PAGE		0x1a
#define GPMODE_FAULT_FAIL_PAGE		0x1c
#define GPMODE_TO_PROTECT_PAGE		0x1d
#define GPMODE_CAPABILITIES_PAGE	0x2a
#define GPMODE_ALL_PAGES		0x3f
/* Not in Mt. Fuji, but in ATAPI 2.6 -- depricated now in favor
 * of MODE_SENSE_POWER_PAGE */
#define GPMODE_CDROM_PAGE		0x0d

/* Some generally useful CD-ROM information */
#define CD_MINS                       80 /* max. minutes per CD */
#define CD_SECS                       60 /* seconds per minute */
#define CD_FRAMES                     75 /* frames per second */
#define CD_FRAMESIZE                2048 /* bytes per frame, "cooked" mode */
#define CD_MAX_BYTES       (CD_MINS * CD_SECS * CD_FRAMES * CD_FRAMESIZE)
#define CD_MAX_SECTORS     (CD_MAX_BYTES / 512)

/* Profile list from MMC-6 revision 1 table 91 */
#define MMC_PROFILE_NONE                0x0000
#define MMC_PROFILE_CD_ROM              0x0008
#define MMC_PROFILE_DVD_ROM             0x0010

#define ATAPI_INT_REASON_CD             0x01 /* 0 = data transfer */
#define ATAPI_INT_REASON_IO             0x02 /* 1 = transfer to the host */
#define ATAPI_INT_REASON_REL            0x04
#define ATAPI_INT_REASON_TAG            0xf8
#define ASC_ILLEGAL_OPCODE                   0x20
#define ASC_LOGICAL_BLOCK_OOR                0x21
#define ASC_INV_FIELD_IN_CMD_PACKET          0x24
#define ASC_MEDIUM_MAY_HAVE_CHANGED          0x28
#define ASC_INCOMPATIBLE_FORMAT              0x30
#define ASC_MEDIUM_NOT_PRESENT               0x3a
#define ASC_SAVING_PARAMETERS_NOT_SUPPORTED  0x39
#define ASC_MEDIA_REMOVAL_PREVENTED          0x53
#define SENSE_NONE            0
#define SENSE_NOT_READY       2
#define SENSE_ILLEGAL_REQUEST 5
#define SENSE_UNIT_ATTENTION  6

#ifdef BUILD_ESP32
#define MAX_MULT_SECTORS 2
#else
#define MAX_MULT_SECTORS 4 /* 512 * 4 == 2048 */
#endif

#ifdef BUILD_ESP32
void *pcmalloc(long size);
#else
#define pcmalloc malloc
#endif

typedef void BlockDeviceCompletionFunc(void *opaque, int ret);

struct BlockDevice {
    int64_t (*get_sector_count)(BlockDevice *bs);
    int (*get_chs)(BlockDevice *bs, int *cylinders, int *heads, int *sectors);
    int (*read_async)(BlockDevice *bs,
                      uint64_t sector_num, uint8_t *buf, int n,
                      BlockDeviceCompletionFunc *cb, void *opaque);
    int (*write_async)(BlockDevice *bs,
                       uint64_t sector_num, const uint8_t *buf, int n,
                       BlockDeviceCompletionFunc *cb, void *opaque);
    void *opaque;
};

typedef struct IDEState IDEState;

typedef void EndTransferFunc(IDEState *);

struct IDEState {
    IDEIFState *ide_if;
    BlockDevice *bs;
    enum {
        IDE_HD, IDE_CD
    } drive_kind;
    int cylinders, heads, sectors;
    int mult_sectors;
    int64_t nb_sectors;

    /* ide regs */
    uint8_t feature;
    uint8_t error;
    uint16_t nsector; /* 0 is 256 to ease computations */
    uint8_t sector;
    uint8_t lcyl;
    uint8_t hcyl;
    uint8_t select;
    uint8_t status;

    /* ATAPI specific */
    uint8_t sense_key;
    uint8_t asc;
    int packet_transfer_size;
    int elementary_transfer_size;
    int io_buffer_index;
    int lba;
    int cd_sector_size;

    int io_nb_sectors;
    int req_nb_sectors;
    EndTransferFunc *end_transfer_func;
    
    int data_index;
    int data_end;
    uint8_t io_buffer[MAX_MULT_SECTORS*512 + 4];
};

struct IDEIFState {
    int irq;
    void *pic;
    void (*set_irq)(void *pic, int irq, int level);

    IDEState *cur_drive;
    IDEState *drives[2];
    /* 0x3f6 command */
    uint8_t cmd;
};

static void ide_sector_read_cb(void *opaque, int ret);
static void ide_sector_read_cb_end(IDEState *s);
static void ide_sector_write_cb2(void *opaque, int ret);

static void padstr(char *str, const char *src, int len)
{
    int i, v;
    for(i = 0; i < len; i++) {
        if (*src)
            v = *src++;
        else
            v = ' ';
        *(char *)((long)str ^ 1) = v;
        str++;
    }
}

static void padstr8(uint8_t *buf, int buf_size, const char *src)
{
    int i;
    for(i = 0; i < buf_size; i++) {
        if (*src)
            buf[i] = *src++;
        else
            buf[i] = ' ';
    }
}

/* little endian assume */
static void stw(uint16_t *buf, int v)
{
    *buf = v;
}

static void ide_identify(IDEState *s)
{
    uint16_t *tab;
    uint32_t oldsize;
    
    tab = (uint16_t *)s->io_buffer;

    memset(tab, 0, 512 * 2);

    stw(tab + 0, 0x0040);
    stw(tab + 1, s->cylinders); 
    stw(tab + 3, s->heads);
    stw(tab + 4, 512 * s->sectors); /* sectors */
    stw(tab + 5, 512); /* sector size */
    stw(tab + 6, s->sectors); 
    stw(tab + 20, 3); /* buffer type */
    stw(tab + 21, 512); /* cache size in sectors */
    stw(tab + 22, 4); /* ecc bytes */
    padstr((char *)(tab + 27), "TINY386 HARDDISK", 40);
    stw(tab + 47, 0x8000 | MAX_MULT_SECTORS);
    stw(tab + 48, 1); /* dword I/O */
    stw(tab + 49, 1 << 9); /* LBA supported, no DMA */
    stw(tab + 51, 0x200); /* PIO transfer cycle */
    stw(tab + 52, 0x200); /* DMA transfer cycle */
    stw(tab + 54, s->cylinders);
    stw(tab + 55, s->heads);
    stw(tab + 56, s->sectors);
    oldsize = s->cylinders * s->heads * s->sectors;
    stw(tab + 57, oldsize);
    stw(tab + 58, oldsize >> 16);
    if (s->mult_sectors)
        stw(tab + 59, 0x100 | s->mult_sectors);
    stw(tab + 60, s->nb_sectors);
    stw(tab + 61, s->nb_sectors >> 16);
    stw(tab + 80, (1 << 1) | (1 << 2));
    stw(tab + 82, (1 << 14));
    stw(tab + 83, (1 << 14));
    stw(tab + 84, (1 << 14));
    stw(tab + 85, (1 << 14));
    stw(tab + 86, 0);
    stw(tab + 87, (1 << 14));
}

static void ide_atapi_identify(IDEState *s)
{
    uint16_t *tab;
    tab = (uint16_t *)s->io_buffer;
    memset(tab, 0, 512 * 2);

    /* Removable CDROM, 50us response, 12 byte packets */
    stw(tab + 0, (2 << 14) | (5 << 8) | (1 << 7) | (2 << 5) | (0 << 0));
    stw(tab + 20, 3); /* buffer type */
    stw(tab + 21, 512); /* cache size in sectors */
    stw(tab + 22, 4); /* ecc bytes */
    padstr((char *)(tab + 27), "TINY386 CD-ROM", 40); /* model */
    stw(tab + 48, 1); /* dword I/O (XXX: should not be set on CDROM) */
    stw(tab + 49, 1 << 9); /* LBA supported, no DMA */
    stw(tab + 53, 3); /* words 64-70, 54-58 valid */
    stw(tab + 63, 0x103); /* DMA modes XXX: may be incorrect */
    stw(tab + 64, 1); /* PIO modes */
    stw(tab + 65, 0xb4); /* minimum DMA multiword tx cycle time */
    stw(tab + 66, 0xb4); /* recommended DMA multiword tx cycle time */
    stw(tab + 67, 0x12c); /* minimum PIO cycle time without flow control */
    stw(tab + 68, 0xb4); /* minimum PIO cycle time with IORDY flow control */

    stw(tab + 71, 30); /* in ns */
    stw(tab + 72, 30); /* in ns */

    stw(tab + 80, 0x1e); /* support up to ATA/ATAPI-4 */
}

static void ide_set_signature(IDEState *s) 
{
    s->select &= 0xf0;
    s->nsector = 1;
    s->sector = 1;
    if (s->drive_kind == IDE_CD) {
        s->lcyl = 0x14;
        s->hcyl = 0xeb;
    } else {
        s->lcyl = 0;
        s->hcyl = 0;
    }
}

static void ide_abort_command(IDEState *s) 
{
    s->status = READY_STAT | ERR_STAT;
    s->error = ABRT_ERR;
}

static void ide_set_irq(IDEState *s) 
{
    IDEIFState *ide_if = s->ide_if;
    if (!(ide_if->cmd & IDE_CMD_DISABLE_IRQ)) {
        ide_if->set_irq(ide_if->pic, ide_if->irq, 1);
    }
}

/* prepare data transfer and tell what to do after */
static void ide_transfer_start(IDEState *s, int size,
                               EndTransferFunc *end_transfer_func)
{
    s->end_transfer_func = end_transfer_func;
    s->data_index = 0;
    s->data_end = size;
}

static void ide_transfer_stop(IDEState *s)
{
    s->end_transfer_func = ide_transfer_stop;
    s->data_index = 0;
    s->data_end = 0;
}

static void ide_transfer_start2(IDEState *s, int off, int size,
                               EndTransferFunc *end_transfer_func)
{
    s->end_transfer_func = end_transfer_func;
    s->data_index = off;
    s->data_end = off + size;
    if (!(s->status & ERR_STAT))
        s->status |= DRQ_STAT;
}

static void ide_transfer_stop2(IDEState *s)
{
    s->end_transfer_func = ide_transfer_stop2;
    s->data_index = 0;
    s->data_end = 0;
    s->status &= ~DRQ_STAT;
}

static int64_t ide_get_sector(IDEState *s)
{
    int64_t sector_num;
    if (s->select & 0x40) {
        /* lba */
        sector_num = ((s->select & 0x0f) << 24) | (s->hcyl << 16) |
            (s->lcyl << 8) | s->sector;
    } else {
        sector_num = ((s->hcyl << 8) | s->lcyl) * 
            s->heads * s->sectors +
            (s->select & 0x0f) * s->sectors + (s->sector - 1);
    }
    return sector_num;
}

static void ide_set_sector(IDEState *s, int64_t sector_num)
{
    unsigned int cyl, r;
    if (s->select & 0x40) {
        s->select = (s->select & 0xf0) | ((sector_num >> 24) & 0x0f);
        s->hcyl = (sector_num >> 16) & 0xff;
        s->lcyl = (sector_num >> 8) & 0xff;
        s->sector = sector_num & 0xff;
    } else {
        cyl = sector_num / (s->heads * s->sectors);
        r = sector_num % (s->heads * s->sectors);
        s->hcyl = (cyl >> 8) & 0xff;
        s->lcyl = cyl & 0xff;
        s->select = (s->select & 0xf0) | ((r / s->sectors) & 0x0f);
        s->sector = (r % s->sectors) + 1;
    }
}

static void ide_sector_read(IDEState *s)
{
    int64_t sector_num;
    int ret, n;

    sector_num = ide_get_sector(s);
    n = s->nsector;
    if (n == 0) 
        n = 256;
    if (n > s->req_nb_sectors)
        n = s->req_nb_sectors;
#if defined(DEBUG_IDE)
    printf("read sector=%" PRId64 " count=%d\n", sector_num, n);
#endif
    s->io_nb_sectors = n;
    ret = s->bs->read_async(s->bs, sector_num, s->io_buffer, n, 
                            ide_sector_read_cb, s);
    if (ret < 0) {
        /* error */
        ide_abort_command(s);
        ide_set_irq(s);
    } else if (ret == 0) {
        /* synchronous case (needed for performance) */
        ide_sector_read_cb(s, 0);
    } else {
        /* async case */
        s->status = READY_STAT | SEEK_STAT | BUSY_STAT;
        s->error = 0; /* not needed by IDE spec, but needed by Windows */
    }
}

static void ide_sector_read_cb(void *opaque, int ret)
{
    IDEState *s = opaque;
    int n;
    EndTransferFunc *func;
    
    n = s->io_nb_sectors;
    ide_set_sector(s, ide_get_sector(s) + n);
    s->nsector = (s->nsector - n) & 0xff;
    if (s->nsector == 0)
        func = ide_sector_read_cb_end;
    else
        func = ide_sector_read;
    ide_transfer_start(s, 512 * n, func);
    ide_set_irq(s);
    s->status = READY_STAT | SEEK_STAT | DRQ_STAT;
    s->error = 0; /* not needed by IDE spec, but needed by Windows */
}

static void ide_sector_read_cb_end(IDEState *s)
{
    /* no more sector to read from disk */
    s->status = READY_STAT | SEEK_STAT;
    s->error = 0; /* not needed by IDE spec, but needed by Windows */
    ide_transfer_stop(s);
}

static void ide_sector_write_cb1(IDEState *s)
{
    int64_t sector_num;
    int ret;

    ide_transfer_stop(s);
    sector_num = ide_get_sector(s);
#if defined(DEBUG_IDE)
    printf("write sector=%" PRId64 "  count=%d\n",
           sector_num, s->io_nb_sectors);
#endif
    ret = s->bs->write_async(s->bs, sector_num, s->io_buffer, s->io_nb_sectors, 
                             ide_sector_write_cb2, s);
    if (ret < 0) {
        /* error */
        ide_abort_command(s);
        ide_set_irq(s);
    } else if (ret == 0) {
        /* synchronous case (needed for performance) */
        ide_sector_write_cb2(s, 0);
    } else {
        /* async case */
        s->status = READY_STAT | SEEK_STAT | BUSY_STAT;
    }
}

static void ide_sector_write_cb2(void *opaque, int ret)
{
    IDEState *s = opaque;
    int n;

    n = s->io_nb_sectors;
    ide_set_sector(s, ide_get_sector(s) + n);
    s->nsector = (s->nsector - n) & 0xff;
    if (s->nsector == 0) {
        /* no more sectors to write */
        s->status = READY_STAT | SEEK_STAT;
    } else {
        n = s->nsector;
        if (n > s->req_nb_sectors)
            n = s->req_nb_sectors;
        s->io_nb_sectors = n;
        ide_transfer_start(s, 512 * n, ide_sector_write_cb1);
        s->status = READY_STAT | SEEK_STAT | DRQ_STAT;
    }
    ide_set_irq(s);
}

static void ide_sector_write(IDEState *s)
{
    int n;
    n = s->nsector;
    if (n == 0)
        n = 256;
    if (n > s->req_nb_sectors)
        n = s->req_nb_sectors;
    s->io_nb_sectors = n;
    ide_transfer_start(s, 512 * n, ide_sector_write_cb1);
    s->status = READY_STAT | SEEK_STAT | DRQ_STAT;
}

static void ide_identify_cb(IDEState *s)
{
    ide_transfer_stop(s);
    s->status = READY_STAT;
}

static void ide_exec_cmd(IDEState *s, int val)
{
#if defined(DEBUG_IDE)
    printf("ide: exec_cmd=0x%02x\n", val);
#endif
    switch(val) {
    case WIN_IDENTIFY:
        ide_identify(s);
        s->status = READY_STAT | SEEK_STAT | DRQ_STAT;
        ide_transfer_start(s, 512, ide_identify_cb);
        ide_set_irq(s);
        break;
    case WIN_SPECIFY:
    case WIN_RECAL:
        s->error = 0;
        s->status = READY_STAT | SEEK_STAT;
        ide_set_irq(s);
        break;
    case WIN_SETMULT:
        if (s->nsector > MAX_MULT_SECTORS || 
            (s->nsector & (s->nsector - 1)) != 0) {
            ide_abort_command(s);
        } else {
            s->mult_sectors = s->nsector;
#if defined(DEBUG_IDE)
            printf("ide: setmult=%d\n", s->mult_sectors);
#endif
            s->status = READY_STAT;
        }
        ide_set_irq(s);
        break;
    case WIN_READ:
    case WIN_READ_ONCE:
        s->req_nb_sectors = 1;
        ide_sector_read(s);
        break;
    case WIN_WRITE:
    case WIN_WRITE_ONCE:
        s->req_nb_sectors = 1;
        ide_sector_write(s);
        break;
    case WIN_MULTREAD:
        if (!s->mult_sectors) {
            ide_abort_command(s);
            ide_set_irq(s);
        } else {
            s->req_nb_sectors = s->mult_sectors;
            ide_sector_read(s);
        }
        break;
    case WIN_MULTWRITE:
        if (!s->mult_sectors) {
            ide_abort_command(s);
            ide_set_irq(s);
        } else {
            s->req_nb_sectors = s->mult_sectors;
            ide_sector_write(s);
        }
        break;
    case WIN_READ_NATIVE_MAX:
        ide_set_sector(s, s->nb_sectors - 1);
        s->status = READY_STAT;
        ide_set_irq(s);
        break;
    default:
        ide_abort_command(s);
        ide_set_irq(s);
        break;
    }
}

static void lba_to_msf(uint8_t *buf, int lba)
{
    lba += 150;
    buf[0] = (lba / 75) / 60;
    buf[1] = (lba / 75) % 60;
    buf[2] = lba % 75;
}

static void cpu_to_be32wu(uint32_t *o, uint32_t v)
{
    *o = __builtin_bswap32(v);
}

static void cpu_to_be16wu(uint16_t *o, uint16_t v)
{
    *o = __builtin_bswap16(v);
}

/* same toc as bochs. Return -1 if error or the toc length */
/* XXX: check this */
static int cdrom_read_toc(int nb_sectors, uint8_t *buf, int msf, int start_track)
{
    uint8_t *q;
    int len;

    if (start_track > 1 && start_track != 0xaa)
        return -1;
    q = buf + 2;
    *q++ = 1; /* first session */
    *q++ = 1; /* last session */
    if (start_track <= 1) {
        *q++ = 0; /* reserved */
        *q++ = 0x14; /* ADR, control */
        *q++ = 1;    /* track number */
        *q++ = 0; /* reserved */
        if (msf) {
            *q++ = 0; /* reserved */
            lba_to_msf(q, 0);
            q += 3;
        } else {
            /* sector 0 */
            cpu_to_be32wu((uint32_t *)q, 0);
            q += 4;
        }
    }
    /* lead out track */
    *q++ = 0; /* reserved */
    *q++ = 0x16; /* ADR, control */
    *q++ = 0xaa; /* track number */
    *q++ = 0; /* reserved */
    if (msf) {
        *q++ = 0; /* reserved */
        lba_to_msf(q, nb_sectors);
        q += 3;
    } else {
        cpu_to_be32wu((uint32_t *)q, nb_sectors);
        q += 4;
    }
    len = q - buf;
    cpu_to_be16wu((uint16_t *)buf, len - 2);
    return len;
}

/* mostly same info as PearPc */
static int cdrom_read_toc_raw(int nb_sectors, uint8_t *buf, int msf, int session_num)
{
    uint8_t *q;
    int len;

    q = buf + 2;
    *q++ = 1; /* first session */
    *q++ = 1; /* last session */

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa0; /* lead-in */
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    *q++ = 0;
    *q++ = 1; /* first track */
    *q++ = 0x00; /* disk type */
    *q++ = 0x00;

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa1;
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    *q++ = 0;
    *q++ = 1; /* last track */
    *q++ = 0x00;
    *q++ = 0x00;

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa2; /* lead-out */
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    if (msf) {
        *q++ = 0; /* reserved */
        lba_to_msf(q, nb_sectors);
        q += 3;
    } else {
        cpu_to_be32wu((uint32_t *)q, nb_sectors);
        q += 4;
    }

    *q++ = 1; /* session number */
    *q++ = 0x14; /* ADR, control */
    *q++ = 0;    /* track number */
    *q++ = 1;    /* point */
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    if (msf) {
        *q++ = 0;
        lba_to_msf(q, 0);
        q += 3;
    } else {
        *q++ = 0;
        *q++ = 0;
        *q++ = 0;
        *q++ = 0;
    }

    len = q - buf;
    cpu_to_be16wu((uint16_t *)buf, len - 2);
    return len;
}

/* XXX: DVDs that could fit on a CD will be reported as a CD */
static inline int media_present(IDEState *s)
{
    return (s->nb_sectors > 0);
}

static inline int media_is_dvd(IDEState *s)
{
    return (media_present(s) && s->nb_sectors > CD_MAX_SECTORS);
}

static inline int media_is_cd(IDEState *s)
{
    return (media_present(s) && s->nb_sectors <= CD_MAX_SECTORS);
}

static void ide_atapi_cmd_ok(IDEState *s)
{
    s->error = 0;
    s->status = READY_STAT | SEEK_STAT;
    s->nsector = (s->nsector & ~7) | ATAPI_INT_REASON_IO | ATAPI_INT_REASON_CD;
    ide_set_irq(s);
}

static void ide_atapi_cmd_error(IDEState *s, int sense_key, int asc)
{
#ifdef DEBUG_IDE_ATAPI
    printf("atapi_cmd_error: sense=0x%x asc=0x%x\n", sense_key, asc);
#endif
    s->error = sense_key << 4;
    s->status = READY_STAT | ERR_STAT;
    s->nsector = (s->nsector & ~7) | ATAPI_INT_REASON_IO | ATAPI_INT_REASON_CD;
    s->sense_key = sense_key;
    s->asc = asc;
    ide_set_irq(s);
}

static void ide_atapi_cmd_check_status(IDEState *s)
{
#ifdef DEBUG_IDE_ATAPI
    printf("atapi_cmd_check_status\n");
#endif
    s->error = MC_ERR | (SENSE_UNIT_ATTENTION << 4);
    s->status = ERR_STAT;
    s->nsector = 0;
    ide_set_irq(s);
}

static inline void cpu_to_ube16(uint8_t *buf, int val)
{
    buf[0] = val >> 8;
    buf[1] = val;
}

static inline void cpu_to_ube32(uint8_t *buf, unsigned int val)
{
    buf[0] = val >> 24;
    buf[1] = val >> 16;
    buf[2] = val >> 8;
    buf[3] = val;
}

static inline int ube16_to_cpu(const uint8_t *buf)
{
    return (buf[0] << 8) | buf[1];
}

static inline int ube32_to_cpu(const uint8_t *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

static int cd_read_sector(BlockDevice *bs, int lba, uint8_t *buf,
                           int sector_size)
{
    int ret;

    switch(sector_size) {
    case 2048:
        ret = bs->read_async(bs, (int64_t)lba << 2, buf, 4,
                             NULL, NULL); // XXX
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

static void ide_atapi_io_error(IDEState *s, int ret)
{
    /* XXX: handle more errors */
    ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                        ASC_LOGICAL_BLOCK_OOR);
}

/* The whole ATAPI transfer logic is handled in this function */
static void ide_atapi_cmd_reply_end(IDEState *s)
{
    int byte_count_limit, size, ret;
#ifdef DEBUG_IDE_ATAPI
    printf("reply: tx_size=%d elem_tx_size=%d index=%d\n",
           s->packet_transfer_size,
           s->elementary_transfer_size,
           s->io_buffer_index);
#endif
    if (s->packet_transfer_size <= 0) {
        /* end of transfer */
        ide_transfer_stop2(s);
        s->status = READY_STAT | SEEK_STAT;
        s->nsector = (s->nsector & ~7) | ATAPI_INT_REASON_IO | ATAPI_INT_REASON_CD;
        ide_set_irq(s);
#ifdef DEBUG_IDE_ATAPI
        printf("status=0x%x\n", s->status);
#endif
    } else {
        /* see if a new sector must be read */
        if (s->lba != -1 && s->io_buffer_index >= s->cd_sector_size) {
            ret = cd_read_sector(s->bs, s->lba, s->io_buffer, s->cd_sector_size);
            if (ret < 0) {
                ide_transfer_stop2(s);
                ide_atapi_io_error(s, ret);
                return;
            }
            s->lba++;
            s->io_buffer_index = 0;
        }
        if (s->elementary_transfer_size > 0) {
            /* there are some data left to transmit in this elementary
               transfer */
            size = s->cd_sector_size - s->io_buffer_index;
            if (size > s->elementary_transfer_size)
                size = s->elementary_transfer_size;
            ide_transfer_start2(s, s->io_buffer_index,
                               size, ide_atapi_cmd_reply_end);
            s->packet_transfer_size -= size;
            s->elementary_transfer_size -= size;
            s->io_buffer_index += size;
        } else {
            /* a new transfer is needed */
            s->nsector = (s->nsector & ~7) | ATAPI_INT_REASON_IO;
            byte_count_limit = s->lcyl | (s->hcyl << 8);
#ifdef DEBUG_IDE_ATAPI
            printf("byte_count_limit=%d\n", byte_count_limit);
            printf("status=0x%x\n", s->status);
#endif
            if (byte_count_limit == 0xffff)
                byte_count_limit--;
            size = s->packet_transfer_size;
            if (size > byte_count_limit) {
                /* byte count limit must be even if this case */
                if (byte_count_limit & 1)
                    byte_count_limit--;
                size = byte_count_limit;
            }
            s->lcyl = size;
            s->hcyl = size >> 8;
            s->elementary_transfer_size = size;
            /* we cannot transmit more than one sector at a time */
            if (s->lba != -1) {
                if (size > (s->cd_sector_size - s->io_buffer_index))
                    size = (s->cd_sector_size - s->io_buffer_index);
            }
            ide_transfer_start2(s, s->io_buffer_index,
                               size, ide_atapi_cmd_reply_end);
            s->packet_transfer_size -= size;
            s->elementary_transfer_size -= size;
            s->io_buffer_index += size;
            ide_set_irq(s);
        }
    }
}

/* send a reply of 'size' bytes in s->io_buffer to an ATAPI command */
static void ide_atapi_cmd_reply(IDEState *s, int size, int max_size)
{
    if (size > max_size)
        size = max_size;
    s->lba = -1; /* no sector read */
    s->packet_transfer_size = size;
//    s->io_buffer_size = size;    /* dma: send the reply data as one chunk */
    s->elementary_transfer_size = 0;
    s->io_buffer_index = 0;

    s->status = READY_STAT | SEEK_STAT;
    ide_atapi_cmd_reply_end(s);
}

/* start a CD-CDROM read command */
static void ide_atapi_cmd_read_pio(IDEState *s, int lba, int nb_sectors,
                                   int sector_size)
{
    s->lba = lba;
    s->packet_transfer_size = nb_sectors * sector_size;
    s->elementary_transfer_size = 0;
    s->io_buffer_index = sector_size;
    s->cd_sector_size = sector_size;

    s->status = READY_STAT | SEEK_STAT;
    ide_atapi_cmd_reply_end(s);
}

static void ide_atapi_cmd_read(IDEState *s, int lba, int nb_sectors,
                               int sector_size)
{
#ifdef DEBUG_IDE_ATAPI
    printf("read %s: LBA=%d nb_sectors=%d\n", 0 ? "dma" : "pio",
	lba, nb_sectors);
#endif
    ide_atapi_cmd_read_pio(s, lba, nb_sectors, sector_size);
}

static inline uint8_t ide_atapi_set_profile(uint8_t *buf, uint8_t *index,
                                            uint16_t profile)
{
    uint8_t *buf_profile = buf + 12; /* start of profiles */

    buf_profile += ((*index) * 4); /* start of indexed profile */
    cpu_to_ube16 (buf_profile, profile);
    buf_profile[2] = ((buf_profile[0] == buf[6]) && (buf_profile[1] == buf[7]));

    /* each profile adds 4 bytes to the response */
    (*index)++;
    buf[11] += 4; /* Additional Length */

    return 4;
}

static void ide_atapi_cmd(IDEState *s)
{
    const uint8_t *packet;
    uint8_t *buf;
    int max_len;

    packet = s->io_buffer;
    buf = s->io_buffer;
#ifdef DEBUG_IDE_ATAPI
    {
        int i;
        printf("ATAPI limit=0x%x packet:", s->lcyl | (s->hcyl << 8));
        for(i = 0; i < ATAPI_PACKET_SIZE; i++) {
            printf(" %02x", packet[i]);
        }
        printf("\n");
    }
#endif
    /* If there's a UNIT_ATTENTION condition pending, only
       REQUEST_SENSE and INQUIRY commands are allowed to complete. */
    if (s->sense_key == SENSE_UNIT_ATTENTION &&
	s->io_buffer[0] != GPCMD_REQUEST_SENSE &&
	s->io_buffer[0] != GPCMD_INQUIRY) {
	ide_atapi_cmd_check_status(s);
	return;
    }
    switch(s->io_buffer[0]) {
    case GPCMD_TEST_UNIT_READY:
        ide_atapi_cmd_ok(s);
        break;
    case GPCMD_MODE_SENSE_6:
    case GPCMD_MODE_SENSE_10:
        {
            int action, code;
            if (packet[0] == GPCMD_MODE_SENSE_10)
                max_len = ube16_to_cpu(packet + 7);
            else
                max_len = packet[4];
            action = packet[2] >> 6;
            code = packet[2] & 0x3f;
            switch(action) {
            case 0: /* current values */
                switch(code) {
                case 0x01: /* error recovery */
                    cpu_to_ube16(&buf[0], 16 + 6);
                    buf[2] = 0x70;
                    buf[3] = 0;
                    buf[4] = 0;
                    buf[5] = 0;
                    buf[6] = 0;
                    buf[7] = 0;

                    buf[8] = 0x01;
                    buf[9] = 0x06;
                    buf[10] = 0x00;
                    buf[11] = 0x05;
                    buf[12] = 0x00;
                    buf[13] = 0x00;
                    buf[14] = 0x00;
                    buf[15] = 0x00;
                    ide_atapi_cmd_reply(s, 16, max_len);
                    break;
                case 0x2a:
                    cpu_to_ube16(&buf[0], 28 + 6);
                    buf[2] = 0x70;
                    buf[3] = 0;
                    buf[4] = 0;
                    buf[5] = 0;
                    buf[6] = 0;
                    buf[7] = 0;

                    buf[8] = 0x2a;
                    buf[9] = 0x12;
                    buf[10] = 0x00;
                    buf[11] = 0x00;

                    /* Claim PLAY_AUDIO capability (0x01) since some Linux
                       code checks for this to automount media. */
                    buf[12] = 0x71;
                    buf[13] = 3 << 5;
                    buf[14] = (1 << 0) | (1 << 3) | (1 << 5);
//                    if (bdrv_is_locked(s->bs))
//                        buf[6] |= 1 << 1;
                    buf[15] = 0x00;
                    cpu_to_ube16(&buf[16], 706);
                    buf[18] = 0;
                    buf[19] = 2;
                    cpu_to_ube16(&buf[20], 512);
                    cpu_to_ube16(&buf[22], 706);
                    buf[24] = 0;
                    buf[25] = 0;
                    buf[26] = 0;
                    buf[27] = 0;
                    ide_atapi_cmd_reply(s, 28, max_len);
                    break;
                default:
                    goto error_cmd;
                }
                break;
            case 1: /* changeable values */
                goto error_cmd;
            case 2: /* default values */
                goto error_cmd;
            default:
            case 3: /* saved values */
                ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                                    ASC_SAVING_PARAMETERS_NOT_SUPPORTED);
                break;
            }
        }
        break;
    case GPCMD_REQUEST_SENSE:
        max_len = packet[4];
        memset(buf, 0, 18);
        buf[0] = 0x70 | (1 << 7);
        buf[2] = s->sense_key;
        buf[7] = 10;
        buf[12] = s->asc;
        if (s->sense_key == SENSE_UNIT_ATTENTION)
            s->sense_key = SENSE_NONE;
        ide_atapi_cmd_reply(s, 18, max_len);
        break;
    case GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL:
        ide_atapi_cmd_ok(s);
        break;
    case GPCMD_READ_10:
    case GPCMD_READ_12:
        {
            int nb_sectors, lba;

            if (packet[0] == GPCMD_READ_10)
                nb_sectors = ube16_to_cpu(packet + 7);
            else
                nb_sectors = ube32_to_cpu(packet + 6);
            lba = ube32_to_cpu(packet + 2);
            if (nb_sectors == 0) {
                ide_atapi_cmd_ok(s);
                break;
            }
            ide_atapi_cmd_read(s, lba, nb_sectors, 2048);
        }
        break;
    case GPCMD_READ_CD:
        {
            int nb_sectors, lba, transfer_request;

            nb_sectors = (packet[6] << 16) | (packet[7] << 8) | packet[8];
            lba = ube32_to_cpu(packet + 2);
            if (nb_sectors == 0) {
                ide_atapi_cmd_ok(s);
                break;
            }
            transfer_request = packet[9];
            switch(transfer_request & 0xf8) {
            case 0x00:
                /* nothing */
                ide_atapi_cmd_ok(s);
                break;
            case 0x10:
                /* normal read */
                ide_atapi_cmd_read(s, lba, nb_sectors, 2048);
                break;
            case 0xf8:
                /* read all data */
                ide_atapi_cmd_read(s, lba, nb_sectors, 2352);
                break;
            default:
                ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                                    ASC_INV_FIELD_IN_CMD_PACKET);
                break;
            }
        }
        break;
    case GPCMD_SEEK:
        {
            unsigned int lba;
            uint64_t total_sectors;

            total_sectors = s->bs->get_sector_count(s->bs);
            total_sectors >>= 2;
            if (total_sectors == 0) {
                ide_atapi_cmd_error(s, SENSE_NOT_READY,
                                    ASC_MEDIUM_NOT_PRESENT);
                break;
            }
            lba = ube32_to_cpu(packet + 2);
            if (lba >= total_sectors) {
                ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                                    ASC_LOGICAL_BLOCK_OOR);
                break;
            }
            ide_atapi_cmd_ok(s);
        }
        break;
    case GPCMD_START_STOP_UNIT:
        {
            ide_atapi_cmd_ok(s);
        }
        break;
    case GPCMD_MECHANISM_STATUS:
        {
            max_len = ube16_to_cpu(packet + 8);
            cpu_to_ube16(buf, 0);
            /* no current LBA */
            buf[2] = 0;
            buf[3] = 0;
            buf[4] = 0;
            buf[5] = 1;
            cpu_to_ube16(buf + 6, 0);
            ide_atapi_cmd_reply(s, 8, max_len);
        }
        break;
    case GPCMD_READ_TOC_PMA_ATIP:
        {
            int format, msf, start_track, len;
            uint64_t total_sectors;

            total_sectors = s->bs->get_sector_count(s->bs);
            total_sectors >>= 2;
            if (total_sectors == 0) {
                ide_atapi_cmd_error(s, SENSE_NOT_READY,
                                    ASC_MEDIUM_NOT_PRESENT);
                break;
            }
            max_len = ube16_to_cpu(packet + 7);
            format = packet[9] >> 6;
            msf = (packet[1] >> 1) & 1;
            start_track = packet[6];
            switch(format) {
            case 0:
                len = cdrom_read_toc(total_sectors, buf, msf, start_track);
                if (len < 0)
                    goto error_cmd;
                ide_atapi_cmd_reply(s, len, max_len);
                break;
            case 1:
                /* multi session : only a single session defined */
                memset(buf, 0, 12);
                buf[1] = 0x0a;
                buf[2] = 0x01;
                buf[3] = 0x01;
                ide_atapi_cmd_reply(s, 12, max_len);
                break;
            case 2:
                len = cdrom_read_toc_raw(total_sectors, buf, msf, start_track);
                if (len < 0)
                    goto error_cmd;
                ide_atapi_cmd_reply(s, len, max_len);
                break;
            default:
            error_cmd:
                ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                                    ASC_INV_FIELD_IN_CMD_PACKET);
                break;
            }
        }
        break;
    case GPCMD_READ_CDVD_CAPACITY:
        {
            uint64_t total_sectors;

            total_sectors = s->bs->get_sector_count(s->bs);
            total_sectors >>= 2;
            if (total_sectors == 0) {
                ide_atapi_cmd_error(s, SENSE_NOT_READY,
                                    ASC_MEDIUM_NOT_PRESENT);
                break;
            }
            /* NOTE: it is really the number of sectors minus 1 */
            cpu_to_ube32(buf, total_sectors - 1);
            cpu_to_ube32(buf + 4, 2048);
            ide_atapi_cmd_reply(s, 8, 8);
        }
        break;
    case GPCMD_SET_SPEED:
        ide_atapi_cmd_ok(s);
        break;
    case GPCMD_INQUIRY:
        max_len = packet[4];
        buf[0] = 0x05; /* CD-ROM */
        buf[1] = 0x80; /* removable */
        buf[2] = 0x00; /* ISO */
        buf[3] = 0x21; /* ATAPI-2 (XXX: put ATAPI-4 ?) */
        buf[4] = 31; /* additional length */
        buf[5] = 0; /* reserved */
        buf[6] = 0; /* reserved */
        buf[7] = 0; /* reserved */
        padstr8(buf + 8, 8, "TINY386");
        padstr8(buf + 16, 16, "TINY386 CD-ROM");
        padstr8(buf + 32, 4, "0.1");
        ide_atapi_cmd_reply(s, 36, max_len);
        break;
    case GPCMD_GET_CONFIGURATION:
        {
            uint32_t len;
            uint8_t index = 0;

            /* only feature 0 is supported */
            if (packet[2] != 0 || packet[3] != 0) {
                ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                                    ASC_INV_FIELD_IN_CMD_PACKET);
                break;
            }

            /* XXX: could result in alignment problems in some architectures */
            max_len = ube16_to_cpu(packet + 7);

            /*
             * XXX: avoid overflow for io_buffer if max_len is bigger than
             *      the size of that buffer (dimensioned to max number of
             *      sectors to transfer at once)
             *
             *      Only a problem if the feature/profiles grow.
             */
            if (max_len > 512) /* XXX: assume 1 sector */
                max_len = 512;

            memset(buf, 0, max_len);
            /* 
             * the number of sectors from the media tells us which profile
             * to use as current.  0 means there is no media
             */
            if (media_is_dvd(s))
                cpu_to_ube16(buf + 6, MMC_PROFILE_DVD_ROM);
            else if (media_is_cd(s))
                cpu_to_ube16(buf + 6, MMC_PROFILE_CD_ROM);

            buf[10] = 0x02 | 0x01; /* persistent and current */
            len = 12; /* headers: 8 + 4 */
            len += ide_atapi_set_profile(buf, &index, MMC_PROFILE_DVD_ROM);
            len += ide_atapi_set_profile(buf, &index, MMC_PROFILE_CD_ROM);
            cpu_to_ube32(buf, len - 4); /* data length */

            ide_atapi_cmd_reply(s, len, max_len);
            break;
        }
    default:
        ide_atapi_cmd_error(s, SENSE_ILLEGAL_REQUEST,
                            ASC_ILLEGAL_OPCODE);
        break;
    }
}

static void idecd_exec_cmd(IDEState *s, int val)
{
#if defined(DEBUG_IDE)
    printf("idecd: exec_cmd=0x%02x\n", val);
#endif
    switch(val) {
    case WIN_DEVICE_RESET:
        //ide_transfer_halt(s);
        //ide_cancel_dma_sync(s);
        //ide_reset(s);
        ide_set_signature(s);
        s->status = 0x00;
        break;
    case WIN_PACKETCMD:
        s->status = READY_STAT | SEEK_STAT;
        s->nsector = 1;
        ide_transfer_start2(s, 0, ATAPI_PACKET_SIZE, ide_atapi_cmd);
        ide_set_irq(s);
        break;
    case WIN_PIDENTIFY:
        ide_atapi_identify(s);
        s->status = READY_STAT | SEEK_STAT;
        ide_transfer_start2(s, 0, 512, ide_transfer_stop2);
        ide_set_irq(s);
        break;
    case WIN_IDENTIFY:
    case WIN_READ:
        ide_set_signature(s);
        /* fall through */
    default:
        ide_abort_command(s);
        ide_set_irq(s);
        break;
    }
}

void ide_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    
#ifdef DEBUG_IDE
    printf("ide: write addr=0x%02x val=0x%02x\n", addr, val);
#endif
    switch(addr) {
    case 0:
        break;
    case 1:
        if (s) {
            s->feature = val;
        }
        break;
    case 2:
        if (s) {
            s->nsector = val;
        }
        break;
    case 3:
        if (s) {
            s->sector = val;
        }
        break;
    case 4:
        if (s) {
            s->lcyl = val;
        }
        break;
    case 5:
        if (s) {
            s->hcyl = val;
        }
        break;
    case 6:
        /* select drive */
        s = s1->cur_drive = s1->drives[(val >> 4) & 1];
        if (s) {
            s->select = val;
        }
        break;
    default:
    case 7:
        /* command */
        if (s) {
            if (s->drive_kind != IDE_CD)
                ide_exec_cmd(s, val);
            else
                idecd_exec_cmd(s, val);
        }
        break;
    }
}

uint32_t ide_ioport_read(void *opaque, uint32_t addr)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int ret;

    if (!s) {
        ret = 0x00;
    } else {
        switch(addr) {
        case 0:
           ret = 0xff;
           break;
        case 1:
            ret = s->error;
            break;
        case 2:
            ret = s->nsector;
            break;
        case 3:
            ret = s->sector;
            break;
        case 4:
            ret = s->lcyl;
            break;
        case 5:
            ret = s->hcyl;
            break;
        case 6:
            ret = s->select;
            break;
        default:
        case 7:
            ret = s->status;
            s1->set_irq(s1->pic, s1->irq, 0);
            break;
        }
    }
#ifdef DEBUG_IDE
    printf("ide: read addr=0x%02x val=0x%02x\n", addr, ret);
#endif
    return ret;
}

uint32_t ide_status_read(void *opaque)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int ret;

    if (s) {
        ret = s->status;
    } else {
        ret = 0;
    }
#ifdef DEBUG_IDE
    printf("ide: read status=0x%02x\n", ret);
#endif
    return ret;
}

void ide_cmd_write(void *opaque, uint32_t val)
{
    IDEIFState *s1 = opaque;
    IDEState *s;
    int i;
    
#ifdef DEBUG_IDE
    printf("ide: cmd write=0x%02x\n", val);
#endif
    if (!(s1->cmd & IDE_CMD_RESET) && (val & IDE_CMD_RESET)) {
        /* low to high */
        for(i = 0; i < 2; i++) {
            s = s1->drives[i];
            if (s) {
                s->status = BUSY_STAT | SEEK_STAT;
                s->error = 0x01;
            }
        }
    } else if ((s1->cmd & IDE_CMD_RESET) && !(val & IDE_CMD_RESET)) {
        /* high to low */
        for(i = 0; i < 2; i++) {
            s = s1->drives[i];
            if (s) {
                s->status = READY_STAT | SEEK_STAT;
                ide_set_signature(s);
            }
        }
    }
    s1->cmd = val;
}

void ide_data_writew(void *opaque, uint32_t val)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int p;
    uint8_t *tab;
    
    if (!s)
        return;
    p = s->data_index;
    if (p + 2 > s->data_end)
        return;
    tab = s->io_buffer;
    tab[p] = val & 0xff;
    tab[p + 1] = (val >> 8) & 0xff;
    p += 2;
    s->data_index = p;
    if (p >= s->data_end)
        s->end_transfer_func(s);
}

uint32_t ide_data_readw(void *opaque)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int p, ret;
    uint8_t *tab;
    
    if (!s) {
        ret = 0;
    } else {
        p = s->data_index;
        if (p + 2 > s->data_end)
            return 0;
        tab = s->io_buffer;
        ret = tab[p] | (tab[p + 1] << 8);
        p += 2;
        s->data_index = p;
        if (p >= s->data_end)
            s->end_transfer_func(s);
    }
    return ret;
}

void ide_data_writel(void *opaque, uint32_t val)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int p;
    uint8_t *tab;
    
    if (!s)
        return;
    p = s->data_index;
    if (p + 4 > s->data_end)
        return;
    tab = s->io_buffer;
    tab[p] = val & 0xff;
    tab[p + 1] = (val >> 8) & 0xff;
    tab[p + 2] = (val >> 16) & 0xff;
    tab[p + 3] = (val >> 24) & 0xff;
    p += 4;
    s->data_index = p;
    if (p >= s->data_end)
        s->end_transfer_func(s);
}

uint32_t ide_data_readl(void *opaque)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    int p, ret;
    uint8_t *tab;
    
    if (!s) {
        ret = 0;
    } else {
        p = s->data_index;
        if (p + 4 > s->data_end)
            return 0;
        tab = s->io_buffer;
        ret = tab[p] | (tab[p + 1] << 8) | (tab[p + 2] << 16) | (tab[p + 3] << 24);
        p += 4;
        s->data_index = p;
        if (p >= s->data_end)
            s->end_transfer_func(s);
    }
    return ret;
}

int ide_data_write_string(void *opaque, uint8_t *buf, int size, int count)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    if (!s)
        return 0;

    int len1 = size * count;
    if (len1 > s->data_end - s->data_index)
        len1 = s->data_end - s->data_index;
    len1 -= len1 % size;
    if (len1 >= 0) {
        memcpy(s->io_buffer + s->data_index, buf, len1);
    }
    s->data_index += len1;
    if (s->data_index >= s->data_end)
        s->end_transfer_func(s);
    return len1 / size;
}

int ide_data_read_string(void *opaque, uint8_t *buf, int size, int count)
{
    IDEIFState *s1 = opaque;
    IDEState *s = s1->cur_drive;
    if (!s)
        return 0;

    int len1 = size * count;
    if (len1 > s->data_end - s->data_index)
        len1 = s->data_end - s->data_index;
    len1 -= len1 % size;
    if (len1 >= 0) {
        memcpy(buf, s->io_buffer + s->data_index, len1);
    }
    s->data_index += len1;
    if (s->data_index >= s->data_end)
        s->end_transfer_func(s);
    return len1 / size;
}

static IDEState *ide_hddrive_init(IDEIFState *ide_if, BlockDevice *bs)
{
    IDEState *s;
    uint32_t cylinders;
    uint64_t nb_sectors;

#ifndef USE_RAWSD
    s = pcmalloc(sizeof(*s));
#else
    s = malloc(sizeof(*s));
#endif
    memset(s, 0, sizeof(*s));

    s->ide_if = ide_if;
    s->bs = bs;
    s->drive_kind = IDE_HD;

    nb_sectors = s->bs->get_sector_count(s->bs);
    cylinders = nb_sectors / (16 * 63);
    if (cylinders > 16383)
        cylinders = 16383;
    else if (cylinders < 2)
        cylinders = 2;
    s->cylinders = cylinders;
    s->heads = 16;
    s->sectors = 63;
    s->nb_sectors = nb_sectors;
    if (s->bs->get_chs)
        s->bs->get_chs(s->bs, &s->cylinders, &s->heads, &s->sectors);

    s->mult_sectors = MAX_MULT_SECTORS;
    /* ide regs */
    s->feature = 0;
    s->error = 0;
    s->nsector = 0;
    s->sector = 0;
    s->lcyl = 0;
    s->hcyl = 0;
    s->select = 0xa0;
    s->status = READY_STAT | SEEK_STAT;

    /* init I/O buffer */
    s->data_index = 0;
    s->data_end = 0;
    s->end_transfer_func = ide_transfer_stop;

    s->req_nb_sectors = 0; /* temp for read/write */
    s->io_nb_sectors = 0; /* temp for read/write */
    return s;
}

static IDEState *ide_cddrive_init(IDEIFState *ide_if, BlockDevice *bs)
{
    IDEState *s;

#ifndef USE_RAWSD
    s = pcmalloc(sizeof(*s));
#else
    s = malloc(sizeof(*s));
#endif
    memset(s, 0, sizeof(*s));

    s->ide_if = ide_if;
    s->bs = bs;
    s->drive_kind = IDE_CD;

    /* ide regs */
    s->feature = 0;
    s->error = 0;
    s->nsector = 0;
    s->sector = 0;
    s->lcyl = 0;
    s->hcyl = 0;
    s->select = 0xa0;
    s->status = READY_STAT | SEEK_STAT;

    ide_set_signature(s);

    /* init I/O buffer */
    s->data_index = 0;
    s->data_end = 0;
    s->end_transfer_func = ide_transfer_stop2;

    s->req_nb_sectors = 0; /* temp for read/write */
    s->io_nb_sectors = 0; /* temp for read/write */
    return s;
}

// old img format
const uint8_t ide_magic[8] = {
  '1','D','E','D','1','5','C','0'
};

typedef enum {
    BF_MODE_RO,
    BF_MODE_RW,
    BF_MODE_SNAPSHOT,
} BlockDeviceModeEnum;

#define SECTOR_SIZE 512

typedef struct BlockDeviceFile {
    FILE *f;
    int start_offset;
    int cylinders, heads, sectors;
    int64_t nb_sectors;
    BlockDeviceModeEnum mode;
    uint8_t **sector_table;
} BlockDeviceFile;

static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceFile *bf = bs->opaque;
    return bf->nb_sectors;
}

static int bf_get_chs(BlockDevice *bs, int *cylinders, int *heads, int *sectors)
{
    BlockDeviceFile *bf = bs->opaque;
    *cylinders = bf->cylinders;
    *heads = bf->heads;
    *sectors = bf->sectors;
    return 0;
}

//#define DUMP_BLOCK_READ

static int bf_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    //    printf("bf_read_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
#ifdef DUMP_BLOCK_READ
    {
        static FILE *f;
        if (!f)
            f = fopen("/tmp/read_sect.txt", "wb");
        fprintf(f, "%" PRId64 " %d\n", sector_num, n);
    }
#endif
    if (!bf->f)
        return -1;
    if (bf->mode == BF_MODE_SNAPSHOT) {
        int i;
        for(i = 0; i < n; i++) {
            if (!bf->sector_table[sector_num]) {
                fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
                fread(buf, 1, SECTOR_SIZE, bf->f);
            } else {
                memcpy(buf, bf->sector_table[sector_num], SECTOR_SIZE);
            }
            sector_num++;
            buf += SECTOR_SIZE;
        }
    } else {
        fseek(bf->f, bf->start_offset + sector_num * SECTOR_SIZE, SEEK_SET);
        fread(buf, 1, n * SECTOR_SIZE, bf->f);
    }
    /* synchronous read */
    return 0;
}

static int bf_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    int ret;

    switch(bf->mode) {
    case BF_MODE_RO:
        ret = -1; /* error */
        break;
    case BF_MODE_RW:
        fseek(bf->f, bf->start_offset + sector_num * SECTOR_SIZE, SEEK_SET);
        fwrite(buf, 1, n * SECTOR_SIZE, bf->f);
        ret = 0;
        break;
    case BF_MODE_SNAPSHOT:
        {
            int i;
            if ((sector_num + n) > bf->nb_sectors)
                return -1;
            for(i = 0; i < n; i++) {
                if (!bf->sector_table[sector_num]) {
                    bf->sector_table[sector_num] = pcmalloc(SECTOR_SIZE);
                }
                memcpy(bf->sector_table[sector_num], buf, SECTOR_SIZE);
                sector_num++;
                buf += SECTOR_SIZE;
            }
            ret = 0;
        }
        break;
    default:
        abort();
    }

    return ret;
}

static BlockDevice *block_device_init(const char *filename,
                                      BlockDeviceModeEnum mode)
{
    BlockDevice *bs;
    BlockDeviceFile *bf;
    int64_t file_size;
    FILE *f;
    const char *mode_str;

    if (mode == BF_MODE_RW) {
        mode_str = "r+b";
    } else {
        mode_str = "rb";
    }
    
    f = fopen(filename, mode_str);
    if (!f) {
        perror(filename);
        exit(1);
    }
    char buf[8];
    int start_offset = 0;
    if (mode == BF_MODE_RO || mode == BF_MODE_RW) {
        fread(buf, 1, 8, f);
        if (memcmp(buf, ide_magic, 8) == 0)
            start_offset = 1024;
    }
    fseek(f, 0, SEEK_END);
    file_size = ftello(f) - start_offset;

    bs = pcmalloc(sizeof(*bs));
    bf = pcmalloc(sizeof(*bf));
    memset(bs, 0, sizeof(*bs));
    memset(bf, 0, sizeof(*bf));

    bf->mode = mode;
    bf->nb_sectors = file_size / 512;
    bf->f = f;
    bf->start_offset = start_offset;

    if (mode == BF_MODE_SNAPSHOT) {
        bf->sector_table = pcmalloc(sizeof(bf->sector_table[0]) *
                                    bf->nb_sectors);
        memset(bf->sector_table, 0,
               sizeof(bf->sector_table[0]) * bf->nb_sectors);
    }
    
    bs->opaque = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->get_chs = NULL;
    if (start_offset) {
        fseek(f, 512, SEEK_SET);
        unsigned char buf[7 * 2];
        fread(buf, 1, 7 * 2, f);
        bf->cylinders = buf[2] | (buf[3] << 8);
        bf->heads = buf[6] | (buf[7] << 8);
        bf->sectors = buf[12] | (buf[13] << 8);
        bs->get_chs = bf_get_chs;
        fseek(f, 0, SEEK_END);
    }
    bs->read_async = bf_read_async;
    bs->write_async = bf_write_async;
    return bs;
}

#ifdef BUILD_ESP32
#include "sdmmc_cmd.h"
typedef struct BlockDeviceESPSD {
    sdmmc_card_t *card;
    int64_t start_sector;
    int64_t nb_sectors;
} BlockDeviceESPSD;

static int64_t espsd_get_sector_count(BlockDevice *bs)
{
    BlockDeviceESPSD *bf = bs->opaque;
    return bf->nb_sectors;
}

//#define DUMP_BLOCK_READ

static int espsd_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceESPSD *bf = bs->opaque;
    if (!bf->card)
        return -1;
    esp_err_t ret;
    ret = sdmmc_read_sectors(bf->card, buf, bf->start_sector + sector_num, n);
    if (ret != 0)
        return -1;
    /* synchronous read */
    return 0;
}

static int espsd_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceESPSD *bf = bs->opaque;
    if (!bf->card)
        return -1;
    esp_err_t ret;
    ret = sdmmc_write_sectors(bf->card, buf, bf->start_sector + sector_num, n);
    if (ret != 0)
        return -1;
    return 0;
}

extern void *rawsd;
static BlockDevice *block_device_init_espsd(int64_t start_sector, int64_t nb_sectors)
{
    sdmmc_card_t *card = rawsd;
    assert(card);
    assert(card->csd.sector_size == 512);
    BlockDevice *bs;
    BlockDeviceESPSD *bf;

    bs = pcmalloc(sizeof(*bs));
    bf = pcmalloc(sizeof(*bf));
    memset(bs, 0, sizeof(*bs));
    memset(bf, 0, sizeof(*bf));
    bf->card = card;
    bf->start_sector = start_sector;
    if (nb_sectors == -1) {
        bf->nb_sectors = card->csd.capacity;
    } else {
        bf->nb_sectors = nb_sectors;
    }
    bs->opaque = bf;
    bs->get_sector_count = espsd_get_sector_count;
    bs->get_chs = NULL;
    bs->read_async = espsd_read_async;
    bs->write_async = espsd_write_async;
    return bs;
}
#endif

IDEIFState *ide_allocate(int irq, void *pic, void (*set_irq)(void *pic, int irq, int level))
{
    int i;
    IDEIFState *s;
    
    s = pcmalloc(sizeof(IDEIFState));
    memset(s, 0, sizeof(*s));

    s->irq = irq;
    s->pic = pic;
    s->set_irq = set_irq;

    s->cur_drive = s->drives[0];
    return s;
}

int ide_attach(IDEIFState *s, int drive, const char *filename)
{
#ifdef BUILD_ESP32
    BlockDevice *bs;
    if (strcmp(filename, "/dev/mmcblk0") == 0) {
        bs = block_device_init_espsd(0, -1);
    } else {
        bs = block_device_init(filename, BF_MODE_RW);
    }
#else
    BlockDevice *bs = block_device_init(filename, BF_MODE_RW);
#endif
    s->drives[drive] = ide_hddrive_init(s, bs);
    return 0;
}

int ide_attach_cd(IDEIFState *s, int drive, const char *filename)
{
    assert(MAX_MULT_SECTORS >= 4);
    BlockDevice *bs = block_device_init(filename, BF_MODE_RO);
    s->drives[drive] = ide_cddrive_init(s, bs);
    return 0;
}

PCIDevice *piix3_ide_init(PCIBus *pci_bus, int devfn)
{
    PCIDevice *d;
    d = pci_register_device(pci_bus, "PIIX3 IDE", devfn, 0x8086, 0x7010, 0x00, 0x0101);
    pci_device_set_config8(d, 0x09, 0x00); /* ISA IDE ports, no DMA */
    return d;
}

void ide_fill_cmos(IDEIFState *s, void *cmos,
                   uint8_t (*set)(void *cmos, int addr, uint8_t val))
{
    // hard disk type, fixes "MS-DOS compatibility mode" in win9x
    uint8_t d_0x12 = 0;
    if (s->drives[0]) {
        d_0x12 |= 0xf0;
        set(cmos, 0x19, 47);
        set(cmos, 0x1b, set(cmos, 0x21, s->drives[0]->cylinders));
        set(cmos, 0x1c, set(cmos, 0x22, s->drives[0]->cylinders >> 8));
        set(cmos, 0x1d, s->drives[0]->heads);
        set(cmos, 0x1e, 0xff);
        set(cmos, 0x1f, 0xff);
        set(cmos, 0x20, 0xc0 | ((s->drives[0]->heads > 8) << 3));
        set(cmos, 0x23, s->drives[0]->sectors);
    }
    if (s->drives[1]) {
        d_0x12 |= 0x0f;
        set(cmos, 0x1a, 47);
        set(cmos, 0x24, set(cmos, 0x2a, s->drives[1]->cylinders));
        set(cmos, 0x25, set(cmos, 0x2b, s->drives[1]->cylinders >> 8));
        set(cmos, 0x26, s->drives[1]->heads);
        set(cmos, 0x27, 0xff);
        set(cmos, 0x28, 0xff);
        set(cmos, 0x29, 0xc0 | ((s->drives[1]->heads > 8) << 3));
        set(cmos, 0x2c, s->drives[1]->sectors);
    }
    set(cmos, 0x12, d_0x12);
}
