/*
 * Hard disk images on the SD card, read and written through FatFs itself
 * with the file's clusters mapped once, when it is opened (FatFs's fast
 * seek).  Through C stdio, ESP-IDF's VFS walks the file's cluster chain
 * in the FAT from its first cluster on every seek backwards, one card read
 * for each FAT sector it passes, and it maps only files opened read only.
 * With an image of a few hundred MB in many pieces, as a card that has
 * been in use for a while holds it, one guest disk access can then take
 * seconds.  ide.c uses this for hard disk images on the card, and stdio
 * as before for anything else.  Needs CONFIG_FATFS_USE_FASTSEEK.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ff.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#define TAG "fatfs_image"

/* where storage.c mounted the card, "/sdcard", and its FatFs drive, "0:" */
static char vol_path[16];
static char vol_drv[4];

void fatfs_image_set_volume(const char *path, int pdrv)
{
	snprintf(vol_path, sizeof(vol_path), "%s", path);
	snprintf(vol_drv, sizeof(vol_drv), "%d:", pdrv);
}

struct fatfs_image {
	FIL fil;
	DWORD *map;
};

/*
 * [esp] fast_seek_kb: the most memory an image's map may take, in KiB; 0
 * maps none, and every image goes through stdio as before.  The map is 8
 * bytes for each piece of the file on the card, and 8 more (at least 256
 * bytes: room for 31 pieces).  Each image mapped also has its own FIL,
 * which holds a sector buffer of FF_MAX_SS bytes unless
 * CONFIG_FATFS_USE_DYN_BUFFERS is set (4,176 bytes with the S3 boards'
 * sdkconfigs; 88, and a 512-byte buffer, with the P4's).  Both go to
 * PSRAM where the heap has some.  On by default on the P4; off on the S3s,
 * whose PSRAM mostly goes to the guest, so that both would come out of
 * internal RAM there.
 */
#ifdef CONFIG_IDF_TARGET_ESP32P4
int fatfs_image_max_kb = 1024;
#else
int fatfs_image_max_kb = 0;
#endif

#if FF_USE_FASTSEEK
/* PSRAM if the heap has some: both are read by the processor only, and
   the SD driver copies what FatFs reads into the FIL's buffer itself */
static void *alloc_prefer_psram(size_t n)
{
	return heap_caps_calloc_prefer(1, n, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_8BIT);
}
#endif

/* path opened through FatFs with its clusters mapped; NULL if mapping is
   off, the file is not on the card, or it would not open or be mapped in
   fast_seek_kb (the caller then uses stdio) */
void *fatfs_image_open(const char *path, int writable)
{
#if FF_USE_FASTSEEK
	size_t l = strlen(vol_path);
	char fpath[256];
	if (fatfs_image_max_kb <= 0 || !l || strncmp(path, vol_path, l) || path[l] != '/' ||
	    snprintf(fpath, sizeof(fpath), "%s%s", vol_drv, path + l) >= (int) sizeof(fpath))
		return NULL;
	struct fatfs_image *d = alloc_prefer_psram(sizeof(*d));
	if (!d) {
		ESP_LOGW(TAG, "%s: no memory for a FIL (%u bytes); through stdio",
			 path, (unsigned) sizeof(*d));
		return NULL;
	}
	if (f_open(&d->fil, fpath, FA_READ | (writable ? FA_WRITE : 0)) != FR_OK) {
		heap_caps_free(d);
		return NULL;
	}
	/* FatFs says how many words the map needs when it is too small */
	DWORD max_words = (DWORD) fatfs_image_max_kb * (1024 / sizeof(DWORD));
	DWORD words = 64;
	FRESULT r;
	for (;;) {
		d->map = alloc_prefer_psram(words * sizeof(DWORD));
		if (!d->map) {
			ESP_LOGW(TAG, "%s: no memory for a map of %u bytes; through stdio",
				 path, (unsigned) (words * sizeof(DWORD)));
			r = FR_NOT_ENOUGH_CORE;
			break;
		}
		d->map[0] = words;
		d->fil.cltbl = d->map;
		r = f_lseek(&d->fil, CREATE_LINKMAP);
		if (r != FR_NOT_ENOUGH_CORE || d->map[0] <= words)
			break;
		DWORD need = d->map[0];
		d->fil.cltbl = NULL;
		heap_caps_free(d->map);
		d->map = NULL;
		if (need > max_words) {
			ESP_LOGW(TAG, "%s: in %u pieces on the card, a map of %u KiB, more than "
				 "fast_seek_kb = %d; through stdio", path, (unsigned) (need - 2) / 2,
				 (unsigned) ((need * sizeof(DWORD) + 1023) / 1024), fatfs_image_max_kb);
			break;
		}
		words = need;
	}
	if (r != FR_OK || !d->map) {
		if (r != FR_OK && r != FR_NOT_ENOUGH_CORE)
			ESP_LOGW(TAG, "%s: clusters not mapped (FatFs error %d); through stdio",
				 path, (int) r);
		d->fil.cltbl = NULL;
		f_close(&d->fil);
		if (d->map)
			heap_caps_free(d->map);
		heap_caps_free(d);
		return NULL;
	}
	unsigned pieces = (d->map[0] - 2) / 2;
	ESP_LOGI(TAG, "%s: in %u piece%s on the card, mapped (%u bytes)", path,
		 pieces, pieces == 1 ? "" : "s", (unsigned) (words * sizeof(DWORD)));
	return d;
#else
	return NULL;
#endif
}

/* len bytes at offset, read or written: 0, or -1 if the range is not
   all in the image (the image is never made longer) or FatFs refused it */
int fatfs_image_rw(void *h, uint64_t offset, void *buf, size_t len, int write)
{
	struct fatfs_image *d = h;
	FRESULT r;
	UINT done = 0;

	if (offset > f_size(&d->fil) || len > f_size(&d->fil) - offset)
		return -1;
	if (f_tell(&d->fil) != offset) {
		r = f_lseek(&d->fil, (FSIZE_t) offset);
		if (r != FR_OK)
			return -1;
	}
	if (write)
		r = f_write(&d->fil, buf, (UINT) len, &done);
	else
		r = f_read(&d->fil, buf, (UINT) len, &done);
	return r == FR_OK && done == len ? 0 : -1;
}
