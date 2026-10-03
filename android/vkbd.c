#include "vkbd.h"
#include <string.h>

extern const uint8_t vgafont16[];
static void draw_string(uint32_t *pixels, int w, int h,
			const char *str, int tx, int ty,
			uint32_t color)
{
	while (*str) {
		uint8_t c = *(uint8_t *) str;
		for (int row = 0; row < 16; row++) {
			uint8_t bits = vgafont16[((int)c) * 16 + row];
			for (int col = 0; col < 8; col++) {
				if (bits & (1 << (7 - col))) {
					int px = tx + col;
					int py = ty + row;
					if (px < w && py < h) {
						pixels[py * w + px] = color;
					}
				}
			}
		}
		tx += 8;
		str++;
	}
}

static void draw_rect(uint32_t *pixels, int w, int h,
		      int rx, int ry, int rw, int rh, uint32_t color)
{
	for (int y = ry; y < ry + rh; y++)
		for (int x = rx; x < rx + rw; x++)
			if (x < w && y < h)
				pixels[y * w + x] = color;
}

static void draw_string_center(
	uint32_t *pixels, int w, int h,
	const char *str, int rx, int ry, int rw, int rh,
	uint32_t color)
{
	int len = strlen(str);
	int sw = len * 8;
	int sh = 16;
	int x = (2 * rx + rw - sw) / 2;
	int y = (2 * ry + rh - sh) / 2;
	draw_string(pixels, w, h, str, x, y, color);
}

void vkbd_draw(uint32_t *pixels, int w, int h, int kx, int ky, bool *kbdinfo)
{
	draw_rect(pixels, w, h, kx, ky,
		  VKBDLAYOUT_W, VKBDLAYOUT_H, vkbd_layout.color);
	for (int i = 0; i < VKBDLAYOUT_LEN; i++) {
		uint32_t fgcolor, bgcolor;
		if (kbdinfo[i]) {
			fgcolor = vkbd_layout.items[i].bgcolor;
			bgcolor = vkbd_layout.items[i].fgcolor;
		} else {
			fgcolor = vkbd_layout.items[i].fgcolor;
			bgcolor = vkbd_layout.items[i].bgcolor;
		}
		draw_rect(pixels, w, h,
			  vkbd_layout.items[i].x, vkbd_layout.items[i].y,
			  vkbd_layout.items[i].w, vkbd_layout.items[i].h,
			  bgcolor);
		draw_string_center(pixels, w, h, vkbd_layout.items[i].text,
				   vkbd_layout.items[i].x, vkbd_layout.items[i].y,
				   vkbd_layout.items[i].w, vkbd_layout.items[i].h,
				   fgcolor);
	}
}

int vkbd_button(int kx, int ky)
{
	for (int i = 0; i < VKBDLAYOUT_LEN; i++) {
		int x1 = vkbd_layout.items[i].x;
		int y1 = vkbd_layout.items[i].y;
		int w1 = vkbd_layout.items[i].w;
		int h1 = vkbd_layout.items[i].h;
		if (kx >= x1 && kx < x1 + w1 &&
		    ky >= y1 && ky < y1 + h1) {
			return i;
		}
	}
	return -1;
}

int vkbd_code(int i)
{
	if (i >= 0 && i < VKBDLAYOUT_LEN)
		return vkbd_layout.items[i].code;
	return 0;
}
