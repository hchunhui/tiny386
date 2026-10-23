#ifndef COMMON_H
#define COMMON_H

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

struct Globals {
	void *pc;
	void *kbd;
	void *mouse;
	void *panel;
	void *panel_fb;   /* RGB panel DMA frame buffer (NULL if not used) */
};

extern EventGroupHandle_t global_event_group;
extern struct Globals globals;

/* fatfs_image.c: hard disk images on the card through FatFs, mapped */
void fatfs_image_set_volume(const char *path, int pdrv);

#endif /* COMMON_H */
