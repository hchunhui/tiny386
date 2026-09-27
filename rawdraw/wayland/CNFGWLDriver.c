#ifndef _CNFGWLDRIVER_C
#define _CNFGWLDRIVER_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-cursor.h>
#include "xdg-shell-client-protocol.h"
#include "pointer-constraints.h"
#include "relative-pointer.h"
#include "keyboard-shortcuts-inhibit.h"

int CNFGRelPos;
#define TITLE_HEIGHT 24
#define QLEN 16

struct AppContext {
	struct wl_display *display;
	struct wl_registry *registry;
	struct wl_compositor *compositor;
	struct wl_shm *shm;
	struct wl_buffer *buffer;
	struct wl_seat *seat;
	struct wl_pointer *pointer;
	struct wl_keyboard *keyboard;
	struct xdg_wm_base *xdg_wm_base;
	struct wl_surface *surface;
	struct xdg_surface *xdg_surface;
	struct xdg_toplevel *xdg_toplevel;

	struct zwp_pointer_constraints_v1 *pointer_constraints;
	struct zwp_locked_pointer_v1 *locked_pointer;
	struct zwp_relative_pointer_manager_v1 *relative_pointer_manager;
	struct zwp_relative_pointer_v1 *relative_pointer;
	struct zwp_keyboard_shortcuts_inhibit_manager_v1 *shortcuts_inhibit_manager;
	struct zwp_keyboard_shortcuts_inhibitor_v1 *inhibitor;

	struct wl_cursor_theme *cursor_theme;
	struct wl_surface *cursor_surface;
	int hotspot_x, hotspot_y;

	int running;
	int w, h;
	void *shm_data;

	int pointer_x;
	int pointer_y;
	int pointer_btn;
	uint32_t last_serial;

	int key_repeat_state;
	int key_repeat_code;
	uint32_t key_repeat_time;

	struct {
		enum {
			CNFGWL_KEYDOWN, CNFGWL_KEYUP,
			CNFGWL_MOTION,
		} type;
		short code0, code;
		short x, y;
	} queue[QLEN];
	int queue_h, queue_t;

	char name[64];
} CNFG_ctx;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1
#endif
int memfd_create_compat(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}
static int create_shm_file(off_t size)
{
	int fd = memfd_create_compat("wayland-shm", MFD_CLOEXEC);
	if (fd < 0) return -1;
	if (ftruncate(fd, size) < 0) { close(fd); return -1; }
	return fd;
}

#include <time.h>
static uint32_t cnfg_get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}

static int cnfg_after_eq(uint32_t a, uint32_t b)
{
    return (a - b) < (1u << 31);
}

extern const uint8_t vgafont16[];
static void draw_string(uint32_t *pixels, int w, int h,
			const char *str, int x, int y,
			uint32_t color)
{
	while (*str) {
		uint8_t c = *(uint8_t *) str;
		for (int row = 0; row < 16; row++) {
			uint8_t bits = vgafont16[((int)c) * 16 + row];
			for (int col = 0; col < 8; col++) {
				if (bits & (1 << (7 - col))) {
					int px = x + col;
					int py = y + row;
					if (px < w && py < h) {
						pixels[py * w + px] = color;
					}
				}
			}
		}
		x += 8;
		str++;
	}
}

static void paint_buffer(void *data, uint32_t *src, int w, int h)
{
	uint32_t *pixels = (uint32_t *)data;
	for (int y = 0; y < TITLE_HEIGHT; y++) {
		for (int x = 0; x < w; x++) pixels[y * w + x] = 0xFF404040;
	}

	int btn_size = TITLE_HEIGHT * 2 / 3;
	int btn_x = w - btn_size - 5;
	int btn_y = (TITLE_HEIGHT - btn_size) / 2;
	for (int y = btn_y; y < btn_y + btn_size; y++)
		for (int x = btn_x; x < btn_x + btn_size; x++)
			pixels[y * w + x] = 0xFFCC1A1A;

	if (src)
		memcpy(pixels + (TITLE_HEIGHT * w), src, w * (h - TITLE_HEIGHT) * 4);
}

static void pointer_common(struct AppContext *app)
{
	if (!CNFGRelPos) {
		if (app->pointer_y < TITLE_HEIGHT) {
			if (app->pointer_btn == 0)
				return;
			app->pointer_btn = 0;
		}
	}

	if ((app->queue_t + 1) % QLEN != app->queue_h) {
		app->queue[app->queue_t].type = CNFGWL_MOTION;
		app->queue[app->queue_t].code0 = app->queue[app->queue_t].code;
		app->queue[app->queue_t].code = app->pointer_btn;
		app->queue[app->queue_t].x = app->pointer_x;
		app->queue[app->queue_t].y = app->pointer_y;
		if (!CNFGRelPos) {
			app->queue[app->queue_t].y -= TITLE_HEIGHT;
		}
		app->queue_t = (app->queue_t + 1) % QLEN;
	}
	app->pointer_btn &= 7;
}

static void pointer_enter(void *data, struct wl_pointer *pointer, uint32_t serial, struct wl_surface *surface, wl_fixed_t x, wl_fixed_t y)
{
	struct AppContext *app = data;
	app->last_serial = serial;
	if (CNFGRelPos)
		wl_pointer_set_cursor(app->pointer, app->last_serial, NULL, 0, 0);
	else
		wl_pointer_set_cursor(app->pointer, app->last_serial, app->cursor_surface,
				      app->hotspot_x, app->hotspot_y);
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial, struct wl_surface *surface)
{
	struct AppContext *app = data;
	app->pointer_btn = 0;
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time, wl_fixed_t x, wl_fixed_t y)
{
	struct AppContext *app = data;
	if (!CNFGRelPos) {
		app->pointer_x = wl_fixed_to_int(x);
		app->pointer_y = wl_fixed_to_int(y);
		pointer_common(app);
	}
}

static int map_btn(int button)
{
	switch (button & 3) {
	case 0: return 1;
	case 1: return 4;
	case 2: return 2;
	}
	return 0;
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state)
{
	struct AppContext *app = data;
	if (CNFGRelPos) {
		app->pointer_x = 0;
		app->pointer_y = 0;
		if (state == 1)
			app->pointer_btn |= map_btn(button);
		else
			app->pointer_btn &= ~map_btn(button);
		pointer_common(app);
		return;
	}

	if (button == 272 && state == 1) {
		int btn_size = 20;
		int btn_x = app->w - btn_size - 5;
		int btn_y = (TITLE_HEIGHT - btn_size) / 2;

		if (app->pointer_x >= btn_x && app->pointer_x <= (btn_x + btn_size) &&
			app->pointer_y >= btn_y && app->pointer_y <= (btn_y + btn_size)) {
			app->running = 0;
			return;
		}

		if (app->pointer_y >= 0 && app->pointer_y < TITLE_HEIGHT) {
			xdg_toplevel_move(app->xdg_toplevel, app->seat, serial);
			return;
		}
	}

	if (app->pointer_y >= TITLE_HEIGHT) {
		if (state == 1)
			app->pointer_btn |= map_btn(button);
		else
			app->pointer_btn &= ~map_btn(button);
		pointer_common(app);
	}
}

static void pointer_axis(void *data, struct wl_pointer *pointer, uint32_t time, uint32_t axis, wl_fixed_t value)
{
	struct AppContext *app = data;
	if (axis == 0) {
		int d = wl_fixed_to_int(value);
		app->pointer_btn &= 7;
		if (d > 0)
			app->pointer_btn |= 16;
		else
			app->pointer_btn |= 8;
		pointer_common(app);
	}
}

static const struct wl_pointer_listener pointer_listener = {
	.enter = pointer_enter,
	.leave = pointer_leave,
	.motion = pointer_motion,
	.button = pointer_button,
	.axis = pointer_axis
};

static void relative_pointer_handle_motion(
	void *data,
	struct zwp_relative_pointer_v1 *wp_relative_pointer,
	uint32_t utime_hi, uint32_t utime_lo,
	wl_fixed_t dx, wl_fixed_t dy,
	wl_fixed_t dx_unaccel, wl_fixed_t dy_unaccel)
{
	struct AppContext *app = data;
	if (CNFGRelPos) {
		int raw_x = wl_fixed_to_int(dx_unaccel);
		int raw_y = wl_fixed_to_int(dy_unaccel);
		app->pointer_x = raw_x;
		app->pointer_y = raw_y;
		pointer_common(app);
	}
}

static const struct zwp_relative_pointer_v1_listener relative_pointer_listener = {
	.relative_motion = relative_pointer_handle_motion,
};

static void keyboard_keymap(void *data, struct wl_keyboard *keyboard, uint32_t format, int fd, uint32_t size)
{
	close(fd);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface, struct wl_array *keys)
{
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface)
{
	struct AppContext *app = data;
	app->key_repeat_state = 0;
}

static bool key_repeats(uint32_t key)
{
	switch (key) {
	case 1: case 29: case 42: case 54: case 56:
	case 97: case 100: case 125: case 126: case 127:
	case 58: case 69: case 70: case 99: case 110:
	case 119:
		return false;
	}
	return true;
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t time, uint32_t key, uint32_t state)
{
	struct AppContext *app = data;
	if ((app->queue_t + 1) % QLEN != app->queue_h) {
		app->queue[app->queue_t].type = state ? CNFGWL_KEYDOWN : CNFGWL_KEYUP;
		app->queue[app->queue_t].code = key;
		app->queue_t = (app->queue_t + 1) % QLEN;

		if (state) {
			if (key_repeats(key)) {
				app->key_repeat_state = 1;
				app->key_repeat_code = key;
				app->key_repeat_time = cnfg_get_uticks() + 500000;
			}
		} else {
			app->key_repeat_state = 0;
		}
	}
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group)
{
}

static void keyboard_repeat_info(void *data, struct wl_keyboard *keyboard, int32_t rate, int32_t delay)
{
	// TODO
}

static const struct wl_keyboard_listener keyboard_listener = {
	.keymap = keyboard_keymap,
	.enter = keyboard_enter,
	.leave = keyboard_leave,
	.key = keyboard_key,
	.modifiers = keyboard_modifiers,
	.repeat_info = keyboard_repeat_info
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities)
{
	struct AppContext *app = data;

	if ((capabilities & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
		app->pointer = wl_seat_get_pointer(seat);
		wl_pointer_add_listener(app->pointer, &pointer_listener, app);

		app->relative_pointer =
			zwp_relative_pointer_manager_v1_get_relative_pointer(
				app->relative_pointer_manager, app->pointer);
		zwp_relative_pointer_v1_add_listener(app->relative_pointer,
						     &relative_pointer_listener,
						     app);
	} else if (!(capabilities & WL_SEAT_CAPABILITY_POINTER) && app->pointer) {
		wl_pointer_destroy(app->pointer);
		app->pointer = NULL;
	}

	if ((capabilities & WL_SEAT_CAPABILITY_KEYBOARD) && !app->keyboard) {
		app->keyboard = wl_seat_get_keyboard(seat);
		wl_keyboard_add_listener(app->keyboard, &keyboard_listener, app);
	}
}

static void seat_name(void *data, struct wl_seat *seat, const char *name)
{
}

static const struct wl_seat_listener seat_listener = {
	.capabilities = seat_capabilities,
	.name = seat_name
};

static void xdg_surface_configure(void *data, struct xdg_surface *xdg_surface, uint32_t serial) {
	struct AppContext *app = data;
	xdg_surface_ack_configure(xdg_surface, serial);

	int stride = app->w * 4;
	int size = stride * app->h;
	int fd = create_shm_file(size);
	if (fd < 0) return;

	void *shm_data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	paint_buffer(shm_data, NULL, app->w, app->h);
	app->shm_data = shm_data;

	struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, size);
	app->buffer = wl_shm_pool_create_buffer(pool, 0, app->w, app->h, stride, WL_SHM_FORMAT_XRGB8888);

	wl_surface_attach(app->surface, app->buffer, 0, 0);
	wl_surface_damage(app->surface, 0, 0, app->w, app->h);
	wl_surface_commit(app->surface);

	close(fd);
	wl_shm_pool_destroy(pool);
}

static const struct xdg_surface_listener xdg_surface_listener = {
	.configure = xdg_surface_configure
};

static void xdg_toplevel_configure(void *data, struct xdg_toplevel *toplevel, int32_t width, int32_t height, struct wl_array *states)
{
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
	((struct AppContext *)data)->running = 0;
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
	.configure = xdg_toplevel_configure,
	.close = xdg_toplevel_close
};

static void wm_base_ping(void *data, struct xdg_wm_base *xdg_wm_base, uint32_t serial)
{
	xdg_wm_base_pong(xdg_wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
	.ping = wm_base_ping
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t id, const char *interface, uint32_t version)
{
	struct AppContext *app = data;
	if (strcmp(interface, "wl_compositor") == 0) {
		app->compositor = wl_registry_bind(registry, id, &wl_compositor_interface, 4);
	} else if (strcmp(interface, "wl_shm") == 0) {
		app->shm = wl_registry_bind(registry, id, &wl_shm_interface, 1);
	} else if (strcmp(interface, "xdg_wm_base") == 0) {
		app->xdg_wm_base = wl_registry_bind(registry, id, &xdg_wm_base_interface, 1);
		xdg_wm_base_add_listener(app->xdg_wm_base, &wm_base_listener, NULL);
	} else if (strcmp(interface, "wl_seat") == 0) {
		app->seat = wl_registry_bind(registry, id, &wl_seat_interface, 1);
		wl_seat_add_listener(app->seat, &seat_listener, app);
	} else if (strcmp(interface, "zwp_pointer_constraints_v1") == 0) {
		app->pointer_constraints = wl_registry_bind(
			registry, id, 
			&zwp_pointer_constraints_v1_interface, 1);
	} else if (strcmp(interface, "zwp_relative_pointer_manager_v1") == 0) {
		app->relative_pointer_manager = wl_registry_bind(
			registry, id,
			&zwp_relative_pointer_manager_v1_interface, 1);
	} else if (strcmp(interface, "zwp_keyboard_shortcuts_inhibit_manager_v1") == 0) {
		app->shortcuts_inhibit_manager = wl_registry_bind(
			registry, id,
			&zwp_keyboard_shortcuts_inhibit_manager_v1_interface, 1);
	}
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t id)
{
}

static const struct wl_registry_listener registry_listener = {
	.global = registry_global,
	.global_remove = registry_global_remove
};

void CNFGConfineMouse_WL( int confined ) {
	struct AppContext *app = &CNFG_ctx;
	if (!app->pointer_constraints)
		return;

	if (confined) {
		CNFGRelPos = 1;
		if (!app->locked_pointer) {
			app->locked_pointer =
				zwp_pointer_constraints_v1_lock_pointer(
					app->pointer_constraints,
					app->surface, app->pointer, NULL,
					ZWP_POINTER_CONSTRAINTS_V1_LIFETIME_PERSISTENT);
			wl_pointer_set_cursor(app->pointer, app->last_serial, NULL, 0, 0);
		}
		if (app->shortcuts_inhibit_manager && !app->inhibitor) {
			app->inhibitor =
				zwp_keyboard_shortcuts_inhibit_manager_v1_inhibit_shortcuts(
					app->shortcuts_inhibit_manager,
					app->surface, app->seat);
		}
	} else {
		CNFGRelPos = 0;
		if (app->locked_pointer) {
			zwp_locked_pointer_v1_destroy(app->locked_pointer);
			app->locked_pointer = NULL;
			wl_pointer_set_cursor(app->pointer, app->last_serial, app->cursor_surface,
					      app->hotspot_x, app->hotspot_y);
		}
		if (app->inhibitor) {
			zwp_keyboard_shortcuts_inhibitor_v1_destroy(
				app->inhibitor);
			app->inhibitor = NULL;
		}
	}
}

void CNFGSetCursor_WL( CNFGCursorShape shape ) {
}

#include <dlfcn.h>
#define __handle __libwayland_handle
#include "wayland_wrapper.c"
static int init_wayland(void)
{
    __handle = dlopen("libwayland-client.so.0", RTLD_NOW);
    return !!__handle;
}
#undef __handle
#define __handle __libwayland_cursor_handle
#include "wayland-cursor_wrapper.c"
static int init_wayland_cursor(void)
{
    __handle = dlopen("libwayland-cursor.so.0", RTLD_NOW);
    return !!__handle;
}
#undef __handle
#include "wayland-protocol.c"
#include "xdg-shell-client-protocol.c"
#include "pointer-constraints.c"
#include "relative-pointer.c"
#include "keyboard-shortcuts-inhibit.c"

int CNFGSetup_WL( const char * WindowName, int w, int h )
{
	if (!init_wayland() || !init_wayland_cursor())
		return 1;

	struct AppContext *app = &CNFG_ctx;
	memset(app, 0, sizeof(CNFG_ctx));
	app->w = w;
	app->h = h + TITLE_HEIGHT;

	app->display = wl_display_connect(NULL);
	if (!app->display) return 1;

	app->registry = wl_display_get_registry(app->display);
	wl_registry_add_listener(app->registry, &registry_listener, &CNFG_ctx);
	wl_display_roundtrip(app->display);

	app->surface = wl_compositor_create_surface(app->compositor);
	app->xdg_surface = xdg_wm_base_get_xdg_surface(app->xdg_wm_base, app->surface);
	xdg_surface_add_listener(app->xdg_surface, &xdg_surface_listener, &CNFG_ctx);

	app->xdg_toplevel = xdg_surface_get_toplevel(app->xdg_surface);
	xdg_toplevel_add_listener(app->xdg_toplevel, &xdg_toplevel_listener, &CNFG_ctx);
	xdg_toplevel_set_title(app->xdg_toplevel, WindowName);
	strncpy(app->name, WindowName, 63);

	wl_surface_commit(app->surface);

	app->cursor_surface = wl_compositor_create_surface(app->compositor);
	app->cursor_theme = wl_cursor_theme_load(NULL, 24, app->shm);
	struct wl_cursor *cursor = wl_cursor_theme_get_cursor(app->cursor_theme, "default");
	if (!cursor || cursor->image_count == 0)
		assert(false);
	struct wl_cursor_image *image = cursor->images[0];
	struct wl_buffer *buffer = wl_cursor_image_get_buffer(image);
	if (!buffer)
		assert(false);
	wl_surface_attach(app->cursor_surface, buffer, 0, 0);
	wl_surface_damage(app->cursor_surface, 0, 0, image->width, image->height);
	app->hotspot_x = image->hotspot_x;
	app->hotspot_y = image->hotspot_y;
	wl_surface_commit(app->cursor_surface);

	app->running = 1;

	return 0;
}

int CNFGHandleInput_WL()
{
	if(!CNFG_ctx.running) return 0;
	struct AppContext *app = &CNFG_ctx;
	struct wl_display *display = app->display;

	if (wl_display_prepare_read(display) == 0) {
		wl_display_read_events(display); 
	} else {
		wl_display_dispatch_pending(display);
	}

	while (wl_display_dispatch_pending(display) > 0);

	wl_display_flush(display);

	if (app->key_repeat_state) {
		uint32_t now = cnfg_get_uticks();
		switch (app->key_repeat_state) {
		case 1:
			if (cnfg_after_eq(now, app->key_repeat_time)) {
				app->key_repeat_state = 2;
			}
			break;
		case 2:
			if (cnfg_after_eq(now, app->key_repeat_time)) {
				app->key_repeat_time = now + 33333;
				if ((app->queue_t + 1) % QLEN != app->queue_h) {
					app->queue[app->queue_t].type = CNFGWL_KEYDOWN;
					app->queue[app->queue_t].code =
						app->key_repeat_code;
					app->queue_t = (app->queue_t + 1) % QLEN;
				}
			}
			break;
		}
	}

	if (app->queue_h != app->queue_t) {
		int code, tmp;
		switch (app->queue[app->queue_h].type) {
		case CNFGWL_KEYDOWN:
		case CNFGWL_KEYUP:
			CNFGLastScancode = app->queue[app->queue_h].code + 8;
			CNFGLastCharacter = 0;
			// XXX
			HandleKey(0, app->queue[app->queue_h].type == CNFGWL_KEYDOWN);
			break;
		case CNFGWL_MOTION:
			code = app->queue[app->queue_h].code;
			tmp = (app->queue[app->queue_h].code0 ^ code) & 7;
			if (tmp) {
				for (int i = 0; i < 3; i++) {
					if (tmp & (1 << i)) {
						if (CNFGRelPos) {
							HandleButtonRel(
								0, 0,
								i + 1,
								!!(code & (1 << i)));
						} else {
							HandleButton(
								app->queue[app->queue_h].x,
								app->queue[app->queue_h].y,
								i + 1,
								!!(code & (1 << i)));
						}
					}
				}
			} else {
				if (!CNFGRelPos) {
					HandleMotion(app->queue[app->queue_h].x,
						     app->queue[app->queue_h].y,
						     app->queue[app->queue_h].code);
				}
			}
			if (CNFGRelPos) {
					HandleMotionRel(app->queue[app->queue_h].x,
							app->queue[app->queue_h].y,
							app->queue[app->queue_h].code);
			}
			break;
		}
		app->queue_h = (app->queue_h + 1) % QLEN;
	}

	return 1;
}

void CNFGUpdateScreenWithBitmap_WL( uint32_t * data, int w, int h )
{
	struct AppContext *app = &CNFG_ctx;
	assert(w == CNFG_ctx.w);
	assert(h == CNFG_ctx.h - TITLE_HEIGHT);
	if (CNFG_ctx.shm_data) {
		paint_buffer(CNFG_ctx.shm_data, data, app->w, app->h);
		draw_string(app->shm_data, app->w, TITLE_HEIGHT,
			    app->name, 4, 4, 0xffdddddd);
		wl_surface_attach(app->surface, app->buffer, 0, 0);
		wl_surface_damage(app->surface, 0, 0, app->w, app->h);
		wl_surface_commit(app->surface);
	}
}

#endif // _CNFGWLDRIVER_C
