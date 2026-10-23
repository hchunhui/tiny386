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

/* the largest map made, in words: two for each piece of the file, and
   two more (1 MiB, 131,071 pieces) */
#define MAX_MAP_WORDS (1 << 18)

/* path opened through FatFs with its clusters mapped; NULL if it is not on
   the card, or would not open or be mapped (the caller then uses stdio) */
void *fatfs_image_open(const char *path, int writable)
{
#if FF_USE_FASTSEEK
	size_t l = strlen(vol_path);
	char fpath[256];
	if (!l || strncmp(path, vol_path, l) || path[l] != '/' ||
	    snprintf(fpath, sizeof(fpath), "%s%s", vol_drv, path + l) >= (int) sizeof(fpath))
		return NULL;
	struct fatfs_image *d = calloc(1, sizeof(*d));
	if (!d)
		return NULL;
	if (f_open(&d->fil, fpath, FA_READ | (writable ? FA_WRITE : 0)) != FR_OK) {
		free(d);
		return NULL;
	}
	/* FatFs says how many words the map needs when it is too small */
	DWORD words = 64;
	FRESULT r;
	for (;;) {
		/* read by the processor only: PSRAM if there is some */
		d->map = heap_caps_malloc_prefer(words * sizeof(DWORD), 2,
						 MALLOC_CAP_SPIRAM, MALLOC_CAP_8BIT);
		if (!d->map) {
			r = FR_NOT_ENOUGH_CORE;
			break;
		}
		d->map[0] = words;
		d->fil.cltbl = d->map;
		r = f_lseek(&d->fil, CREATE_LINKMAP);
		if (r != FR_NOT_ENOUGH_CORE || d->map[0] <= words ||
		    d->map[0] > MAX_MAP_WORDS)
			break;
		words = d->map[0];
		d->fil.cltbl = NULL;
		heap_caps_free(d->map);
	}
	if (r != FR_OK) {
		ESP_LOGW(TAG, "%s: clusters not mapped (FatFs error %d)", path, (int) r);
		d->fil.cltbl = NULL;
		f_close(&d->fil);
		if (d->map)
			heap_caps_free(d->map);
		free(d);
		return NULL;
	}
	ESP_LOGI(TAG, "%s: in %u pieces on the card, mapped", path,
		 (unsigned) (d->map[0] - 2) / 2);
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
