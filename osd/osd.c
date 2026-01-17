#include "osd.h"
#include "microui.h"
#include "atlas.inl"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../vga.h" // XXX: for BPP definition

#include "../misc.h"
#include "../ide.h"

struct OSD {
	mu_Context ctx;
	EMULINK *emulink;
	IDEIFState *ide, *ide2;
	void *console;
};

static void do_window(mu_Context *ctx, struct OSD *osd)
{
	if (mu_begin_window_ex(ctx, "Tiny386 Control Panel",
			       mu_rect(40, 40, 320, 240),
			       MU_OPT_NOCLOSE)) {
		static char buf[2][128];
		mu_layout_row(ctx, 3, (int[]) { 54, -70, -1 }, 0);
		for (int i = 0; i < 2; i++) {
			mu_push_id(ctx, &i, sizeof(i));
			char label[4] = "fd ";
			label[2] = 'a' + i;
			mu_label(ctx, label);
			if (mu_textbox(ctx, buf[i], sizeof(buf[0])) & MU_RES_SUBMIT) {
//				mu_set_focus(ctx, ctx->last_id);
			}
			if (mu_button(ctx, "Submit")) {
				if (osd->emulink) {
					if (buf[i][0] == 0)
						emulink_attach_floppy(osd->emulink, i, NULL);
					else
						emulink_attach_floppy(osd->emulink, i, buf[i]);
				}
			}
			mu_pop_id(ctx);
		}

		static char buf2[4][128];
		for (int i = 0; i < 4; i++) {
			int iid = 2 + i;
			mu_push_id(ctx, &iid, sizeof(iid));
			char label[4] = "cd ";
			label[2] = 'a' + i;
			mu_label(ctx, label);
			if (mu_textbox(ctx, buf2[i], sizeof(buf2[0])) & MU_RES_SUBMIT) {
//				mu_set_focus(ctx, ctx->last_id);
			}
			if (mu_button(ctx, "Submit")) {
				IDEIFState *ide;
				if (i < 2) {
					ide = osd->ide;
				} else {
					ide = osd->ide2;
				}
				if (ide)
					ide_change_cd(ide, i % 2, buf2[i]);
			}
			mu_pop_id(ctx);
		}

		if (osd->console) {
			void __attribute__((weak)) console_send_kbd(void *opaque, int keypress, int keycode);
			if (console_send_kbd) {
				mu_layout_row(ctx, 3, (int[]) { 75, 75, 75 }, 0);
				if (mu_button(ctx, "Ctrl+Alt+Del")) {
					console_send_kbd(osd->console, 1, 0x1d);
					console_send_kbd(osd->console, 1, 0x38);
					console_send_kbd(osd->console, 1, 0x53);
					console_send_kbd(osd->console, 0, 0x53);
					console_send_kbd(osd->console, 0, 0x38);
					console_send_kbd(osd->console, 0, 0x1d);
				}
				if (mu_button(ctx, "Ctrl+[")) {
					console_send_kbd(osd->console, 1, 0x1d);
					console_send_kbd(osd->console, 1, 0x1a);
					console_send_kbd(osd->console, 0, 0x1a);
					console_send_kbd(osd->console, 0, 0x1d);
				}
				if (mu_button(ctx, "Ctrl+]")) {
					console_send_kbd(osd->console, 1, 0x1d);
					console_send_kbd(osd->console, 1, 0x1b);
					console_send_kbd(osd->console, 0, 0x1b);
					console_send_kbd(osd->console, 0, 0x1d);
				}
			}
		}
		mu_end_window(ctx);
	}
}

static void process_frame(mu_Context *ctx, struct OSD *osd)
{
	mu_begin(ctx);
	do_window(ctx, osd);
	mu_end(ctx);
}

// raw render
static int text_width(mu_Font font, const char *text, int len)
{
	int res = 0;
	for (const char *p = text; *p && len--; p++) {
		if ((*p & 0xc0) == 0x80) { continue; }
		int chr = mu_min((unsigned char) *p, 127);
		res += atlas[ATLAS_FONT + chr].w;
	}
	return res;
}

static int text_height(mu_Font font)
{
	return 18;
}

static const char kb_ascii[2][128] =
{
	{
		0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0, 0,
		'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0, 0,
		'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
		'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, 0, 0, ' ',
	},
	{
		0, 0, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0, 0,
		'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 0, 0,
		'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|',
		'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, 0, 0, ' ',
	},
};

static char scancode_trans(int code, int i)
{
	return kb_ascii[i][code & 0x7f];
}

static void render(mu_Context *ctx,
		   uint8_t *pixels,
		   int w, int h, int pitch)
{
	mu_Command *cmd = NULL;
	int clipx = 0;
	int clipy = 0;
	int clipw = 0x1000000;
	int cliph = 0x1000000;
	while(mu_next_command(ctx, &cmd)) {
		switch (cmd->type) {
		case MU_COMMAND_TEXT: {
			int destx = cmd->text.pos.x;
			int desty = cmd->text.pos.y;

			for(const char *p = cmd->text.str; *p; p++) {
				if((*p & 0xc0) == 0x80) { continue; }
				int chr = mu_min((unsigned char) *p, 127);
				mu_Rect src = atlas[ATLAS_FONT + chr];
				int srcx = src.x;
				int srcy = src.y;
				int srcw = src.w;
				int srch = src.h;

				for (int y = 0; y < srch; y++) {
					if (y + desty < clipy || y + desty >= clipy + cliph || y + desty >= h)
						continue;
					for (int x = 0; x < srcw; x++) {
						if (x + destx < clipx || x + destx >= clipx + clipw || x + destx >= w)
							continue;
						uint8_t c = atlas_texture[(y + srcy) * 128 + (x + srcx)];
						if (c) {
#if BPP == 32
							uint32_t cc = c | (c << 8) | (c << 16) | (255 << 24);
							*(uint32_t *)&(pixels[(y + desty) * pitch + 4 * (x + destx)]) = cc;
#elif BPP == 16
							uint16_t cc = (c >> 3) | ((c >> 2) << 5) | ((c >> 3) << 11);
							*(uint16_t *)&(pixels[(y + desty) * pitch + 2 * (x + destx)]) = cc;
#else
#error "bad bpp"
#endif
						}
					}
				}
				destx += srcw;
			}
			break;
		}
		case MU_COMMAND_RECT: {
			int rectx = cmd->rect.rect.x;
			int recty = cmd->rect.rect.y;
			int rectw = cmd->rect.rect.w;
			int recth = cmd->rect.rect.h;
#if BPP == 32
			uint32_t cc = cmd->rect.color.b | (cmd->rect.color.g << 8) |
				(cmd->rect.color.r << 16) | (cmd->rect.color.a << 24);
#elif BPP == 16
			uint16_t cc = (cmd->rect.color.b >> 3) | ((cmd->rect.color.g >> 2) << 5) |
				((cmd->rect.color.r >> 3) << 11);
#else
#error "bad bpp"
#endif
			for (int y = recty; y < recty + recth; y++) {
				if (y < clipy || y >= clipy + cliph || y >= h)
					continue;
				for (int x = rectx; x < rectx + rectw; x++) {
					if (x < clipx || x >= clipx + clipw || x >= w)
						continue;
#if BPP == 32
					*(uint32_t *)&(pixels[y * pitch + 4 * x]) = cc;
#elif BPP == 16
					*(uint16_t *)&(pixels[y * pitch + 2 * x]) = cc;
#else
#error "bad bpp"
#endif
				}
			}
			break;
		}
		case MU_COMMAND_ICON: {
			int rectx = cmd->icon.rect.x;
			int recty = cmd->icon.rect.y;
			int rectw = cmd->icon.rect.w;
			int recth = cmd->icon.rect.h;
			mu_Rect r = atlas[cmd->icon.id];
			recty += (recth - r.h) / 2;
			rectx += (rectw - r.w) / 2;
			for (int y = 0; y < r.h; y++) {
				if (y + recty < clipy || y + recty >= clipy + cliph || y + recty >= h)
					continue;
				for (int x = 0; x < r.w; x++) {
					if (x + rectx < clipx || x + rectx >= clipx + clipw || x + rectx >= w)
						continue;
					uint8_t c = atlas_texture[(y + r.y) * 128 + (x + r.x)];
#if BPP == 32
					uint32_t cc = c | (c << 8) | (c << 16) | (255 << 24);
					*(uint32_t *)&(pixels[(y + recty) * pitch + 4 * (x + rectx)]) = cc;
#elif BPP == 16
					uint16_t cc = (c >> 3) | ((c >> 2) << 5) | ((c >> 3) << 11);
					*(uint16_t *)&(pixels[(y + recty) * pitch + 2 * (x + rectx)]) = cc;
#else
#error "bad bpp"
#endif

				}
			}
			break;
		}
		case MU_COMMAND_CLIP: {
			clipx = cmd->clip.rect.x;
			clipy = cmd->clip.rect.y;
			clipw = cmd->clip.rect.w;
			cliph = cmd->clip.rect.h;
			break;
		}
		}
	}

	// draw cursor
	if (ctx->mouse_pos.x || ctx->mouse_pos.y || ctx->last_mouse_pos.x || ctx->last_mouse_pos.y) {
#if BPP == 32
		uint32_t cc = 255 | (255 << 8) |
			(255 << 16) | (255 << 24);
#elif BPP == 16
		uint16_t cc = (255 >> 3) | ((255 >> 2) << 5) |
			((255 >> 3) << 11);
#else
#error "bad bpp"
#endif
		for (int y = ctx->mouse_pos.y; y < ctx->mouse_pos.y + 8; y++) {
			if (y < 0 || y + 8 >= h)
				continue;
			for (int x = ctx->mouse_pos.x; x < ctx->mouse_pos.x + 8; x++) {
				if (x < 0 || x + 8 >= w)
					continue;
				if (x - ctx->mouse_pos.x > 5 - (y - ctx->mouse_pos.y) &&
				    x - ctx->mouse_pos.x != y - ctx->mouse_pos.y)
					continue;
#if BPP == 32
				*(uint32_t *)&(pixels[y * pitch + 4 * x]) = cc;
#elif BPP == 16
				*(uint16_t *)&(pixels[y * pitch + 2 * x]) = cc;
#else
#error "bad bpp"
#endif
			}
		}
	}
}

OSD *osd_init()
{
	OSD *osd = malloc(sizeof(OSD));
	osd->emulink = NULL;
	osd->ide = osd->ide2 = NULL;
	osd->console = NULL;
	mu_init(&(osd->ctx));
	osd->ctx.text_height = text_height;
	osd->ctx.text_width = text_width;
	return osd;
}

void osd_attach_emulink(OSD *osd, void *emulink)
{
	osd->emulink = emulink;
}

void osd_attach_ide(OSD *osd, void *ide, void *ide2)
{
	osd->ide = ide;
	osd->ide2 = ide2;
}

void osd_attach_console(OSD *osd, void *console)
{
	osd->console = console;
}

void osd_handle_mouse_motion(OSD *osd, int x, int y)
{
	mu_input_mousemove(&(osd->ctx), x, y);
}

void osd_handle_mouse_button(OSD *osd, int x, int y, int down, int btn)
{
	int b = 0;
	switch (btn) {
	case 1: b = MU_MOUSE_LEFT; break;
	case 2: b = MU_MOUSE_RIGHT; break;
	case 4: b = MU_MOUSE_MIDDLE; break;
	}
	if (b) {
		if (down)
			mu_input_mousedown(&(osd->ctx), x, y, b);
		else
			mu_input_mouseup(&(osd->ctx), x, y, b);
	}
}

void osd_handle_key(OSD *osd, int keycode, int down)
{
	int c = 0;
	switch (keycode) {
	case 0x1c: c = MU_KEY_RETURN; break;
	case 0x0e: c = MU_KEY_BACKSPACE; break;
	case 0x2a: case 0x36: c = MU_KEY_SHIFT; break;
	case 0x1d: case 0x61: c = MU_KEY_CTRL; break;
	case 0x38: case 0x64: c = MU_KEY_ALT; break;
	}
	if (c) {
		if (down)
			mu_input_keydown(&(osd->ctx), c);
		else
			mu_input_keyup(&(osd->ctx), c);
	}
	if (down) {
		char buf[2] = {0, 0};
		buf[0] = scancode_trans(keycode, osd->ctx.key_down & MU_KEY_SHIFT);
		if (buf[0])
			mu_input_text(&(osd->ctx), buf);
	}
}

void osd_render(OSD *osd, uint8_t *pixels, int w, int h, int pitch)
{
	process_frame(&(osd->ctx), osd);
	render(&(osd->ctx), pixels, w, h, pitch);
}
