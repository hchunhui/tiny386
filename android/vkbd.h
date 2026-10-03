#ifndef VKBD_H
#define VKBD_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "vkbd_layout.inc"

int vkbd_button(int kx, int ky);
void vkbd_draw(uint32_t *pixels, int w, int h, int kx, int ky, bool *kbdinfo);
int vkbd_code(int i);

#endif /* VKBD_H */
