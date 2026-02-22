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

#endif /* COMMON_H */
