
struct VKBDLayout {
	uint32_t color;
	struct {
		int x, y, w, h;
		const char *text;
		uint32_t bgcolor, fgcolor;
		int code;
	} items[];
};

const static struct VKBDLayout vkbd_layout = {
	0xffd1d4d9,
	{
		{ 10, 10, 35, 41, "Esc", 0xffabb2bb, 0xff000000, 0x1 },
		{ 50, 10, 35, 41, "F1", 0xffabb2bb, 0xff000000, 0x3b },
		{ 90, 10, 35, 41, "F2", 0xffabb2bb, 0xff000000, 0x3c },
		{ 130, 10, 35, 41, "F3", 0xffabb2bb, 0xff000000, 0x3d },
		{ 170, 10, 35, 41, "F4", 0xffabb2bb, 0xff000000, 0x3e },
		{ 210, 10, 35, 41, "F5", 0xffabb2bb, 0xff000000, 0x3f },
		{ 250, 10, 35, 41, "F6", 0xffabb2bb, 0xff000000, 0x40 },
		{ 290, 10, 35, 41, "F7", 0xffabb2bb, 0xff000000, 0x41 },
		{ 330, 10, 35, 41, "F8", 0xffabb2bb, 0xff000000, 0x42 },
		{ 370, 10, 35, 41, "F9", 0xffabb2bb, 0xff000000, 0x43 },
		{ 410, 10, 35, 41, "F10", 0xffabb2bb, 0xff000000, 0x44 },
		{ 450, 10, 35, 41, "F11", 0xffabb2bb, 0xff000000, 0x57 },
		{ 490, 10, 35, 41, "F12", 0xffabb2bb, 0xff000000, 0x58 },
		{ 530, 10, 53, 41, "PgUp", 0xffabb2bb, 0xff000000, 0xe049 },
		{ 588, 10, 53, 41, "PgDn", 0xffabb2bb, 0xff000000, 0xe051 },
		{ 39, 59, 35, 41, "`", 0xffffffff, 0xff000000, 0x29 },
		{ 79, 59, 35, 41, "1", 0xffffffff, 0xff000000, 0x2 },
		{ 119, 59, 35, 41, "2", 0xffffffff, 0xff000000, 0x3 },
		{ 159, 59, 35, 41, "3", 0xffffffff, 0xff000000, 0x4 },
		{ 199, 59, 35, 41, "4", 0xffffffff, 0xff000000, 0x5 },
		{ 239, 59, 35, 41, "5", 0xffffffff, 0xff000000, 0x6 },
		{ 279, 59, 35, 41, "6", 0xffffffff, 0xff000000, 0x7 },
		{ 319, 59, 35, 41, "7", 0xffffffff, 0xff000000, 0x8 },
		{ 359, 59, 35, 41, "8", 0xffffffff, 0xff000000, 0x9 },
		{ 399, 59, 35, 41, "9", 0xffffffff, 0xff000000, 0xa },
		{ 439, 59, 35, 41, "0", 0xffffffff, 0xff000000, 0xb },
		{ 479, 59, 35, 41, "-", 0xffffffff, 0xff000000, 0xc },
		{ 519, 59, 35, 41, "=", 0xffffffff, 0xff000000, 0xd },
		{ 559, 59, 53, 41, "Back", 0xffabb2bb, 0xff000000, 0xe },
		{ 39, 108, 53, 41, "Tab", 0xffabb2bb, 0xff000000, 0xf },
		{ 96, 108, 35, 41, "Q", 0xffffffff, 0xff000000, 0x10 },
		{ 136, 108, 35, 41, "W", 0xffffffff, 0xff000000, 0x11 },
		{ 176, 108, 35, 41, "E", 0xffffffff, 0xff000000, 0x12 },
		{ 216, 108, 35, 41, "R", 0xffffffff, 0xff000000, 0x13 },
		{ 256, 108, 35, 41, "T", 0xffffffff, 0xff000000, 0x14 },
		{ 296, 108, 35, 41, "Y", 0xffffffff, 0xff000000, 0x15 },
		{ 336, 108, 35, 41, "U", 0xffffffff, 0xff000000, 0x16 },
		{ 376, 108, 35, 41, "I", 0xffffffff, 0xff000000, 0x17 },
		{ 416, 108, 35, 41, "O", 0xffffffff, 0xff000000, 0x18 },
		{ 456, 108, 35, 41, "P", 0xffffffff, 0xff000000, 0x19 },
		{ 496, 108, 35, 41, "[", 0xffffffff, 0xff000000, 0x1a },
		{ 536, 108, 35, 41, "]", 0xffffffff, 0xff000000, 0x1b },
		{ 576, 108, 35, 41, "\\", 0xffffffff, 0xff000000, 0x2b },
		{ 50, 157, 53, 41, "Caps", 0xffabb2bb, 0xff000000, 0x3a },
		{ 108, 157, 35, 41, "A", 0xffffffff, 0xff000000, 0x1e },
		{ 148, 157, 35, 41, "S", 0xffffffff, 0xff000000, 0x1f },
		{ 188, 157, 35, 41, "D", 0xffffffff, 0xff000000, 0x20 },
		{ 228, 157, 35, 41, "F", 0xffffffff, 0xff000000, 0x21 },
		{ 268, 157, 35, 41, "G", 0xffffffff, 0xff000000, 0x22 },
		{ 308, 157, 35, 41, "H", 0xffffffff, 0xff000000, 0x23 },
		{ 348, 157, 35, 41, "J", 0xffffffff, 0xff000000, 0x24 },
		{ 388, 157, 35, 41, "K", 0xffffffff, 0xff000000, 0x25 },
		{ 428, 157, 35, 41, "L", 0xffffffff, 0xff000000, 0x26 },
		{ 468, 157, 35, 41, ";", 0xffffffff, 0xff000000, 0x27 },
		{ 508, 157, 35, 41, "'", 0xffffffff, 0xff000000, 0x28 },
		{ 548, 157, 53, 41, "Enter", 0xffabb2bb, 0xff000000, 0x1c },
		{ 70, 206, 53, 41, "Shift", 0xffabb2bb, 0xff000000, 0x2a },
		{ 128, 206, 35, 41, "Z", 0xffffffff, 0xff000000, 0x2c },
		{ 168, 206, 35, 41, "X", 0xffffffff, 0xff000000, 0x2d },
		{ 208, 206, 35, 41, "C", 0xffffffff, 0xff000000, 0x2e },
		{ 248, 206, 35, 41, "V", 0xffffffff, 0xff000000, 0x2f },
		{ 288, 206, 35, 41, "B", 0xffffffff, 0xff000000, 0x30 },
		{ 328, 206, 35, 41, "N", 0xffffffff, 0xff000000, 0x31 },
		{ 368, 206, 35, 41, "M", 0xffffffff, 0xff000000, 0x32 },
		{ 408, 206, 35, 41, ",", 0xffffffff, 0xff000000, 0x33 },
		{ 448, 206, 35, 41, ".", 0xffffffff, 0xff000000, 0x34 },
		{ 488, 206, 35, 41, "/", 0xffffffff, 0xff000000, 0x35 },
		{ 528, 206, 53, 41, "Up", 0xffabb2bb, 0xff000000, 0xe048 },
		{ 13, 255, 53, 41, "Ctrl", 0xffabb2bb, 0xff000000, 0x1d },
		{ 70, 255, 53, 41, "Alt", 0xffabb2bb, 0xff000000, 0x38 },
		{ 128, 255, 280, 41, "Space", 0xffffffff, 0xff000000, 0x39 },
		{ 413, 255, 53, 41, "Del", 0xffabb2bb, 0xff000000, 0xe053 },
		{ 470, 255, 53, 41, "Left", 0xffabb2bb, 0xff000000, 0xe04b },
		{ 528, 255, 53, 41, "Down", 0xffabb2bb, 0xff000000, 0xe050 },
		{ 585, 255, 53, 41, "Right", 0xffabb2bb, 0xff000000, 0xe04d },
		{ 0, 0, 0, 0, NULL, 0, 0 }
	}
};
#define VKBDLAYOUT_LEN 75
#define VKBDLAYOUT_W 650
#define VKBDLAYOUT_H 306

