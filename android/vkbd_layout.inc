
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
		{ 0, 0, 650, 25, "---", 0xffabb2bb, 0xffffffff, -0x1 },
		{ 10, 38, 35, 41, "Esc", 0xffabb2bb, 0xff000000, 0x1 },
		{ 50, 38, 35, 41, "F1", 0xffabb2bb, 0xff000000, 0x3b },
		{ 90, 38, 35, 41, "F2", 0xffabb2bb, 0xff000000, 0x3c },
		{ 130, 38, 35, 41, "F3", 0xffabb2bb, 0xff000000, 0x3d },
		{ 170, 38, 35, 41, "F4", 0xffabb2bb, 0xff000000, 0x3e },
		{ 210, 38, 35, 41, "F5", 0xffabb2bb, 0xff000000, 0x3f },
		{ 250, 38, 35, 41, "F6", 0xffabb2bb, 0xff000000, 0x40 },
		{ 290, 38, 35, 41, "F7", 0xffabb2bb, 0xff000000, 0x41 },
		{ 330, 38, 35, 41, "F8", 0xffabb2bb, 0xff000000, 0x42 },
		{ 370, 38, 35, 41, "F9", 0xffabb2bb, 0xff000000, 0x43 },
		{ 410, 38, 35, 41, "F10", 0xffabb2bb, 0xff000000, 0x44 },
		{ 450, 38, 35, 41, "F11", 0xffabb2bb, 0xff000000, 0x57 },
		{ 490, 38, 35, 41, "F12", 0xffabb2bb, 0xff000000, 0x58 },
		{ 530, 38, 53, 41, "PgUp", 0xffabb2bb, 0xff000000, 0xe049 },
		{ 588, 38, 53, 41, "PgDn", 0xffabb2bb, 0xff000000, 0xe051 },
		{ 39, 87, 35, 41, "`", 0xffffffff, 0xff000000, 0x29 },
		{ 79, 87, 35, 41, "1", 0xffffffff, 0xff000000, 0x2 },
		{ 119, 87, 35, 41, "2", 0xffffffff, 0xff000000, 0x3 },
		{ 159, 87, 35, 41, "3", 0xffffffff, 0xff000000, 0x4 },
		{ 199, 87, 35, 41, "4", 0xffffffff, 0xff000000, 0x5 },
		{ 239, 87, 35, 41, "5", 0xffffffff, 0xff000000, 0x6 },
		{ 279, 87, 35, 41, "6", 0xffffffff, 0xff000000, 0x7 },
		{ 319, 87, 35, 41, "7", 0xffffffff, 0xff000000, 0x8 },
		{ 359, 87, 35, 41, "8", 0xffffffff, 0xff000000, 0x9 },
		{ 399, 87, 35, 41, "9", 0xffffffff, 0xff000000, 0xa },
		{ 439, 87, 35, 41, "0", 0xffffffff, 0xff000000, 0xb },
		{ 479, 87, 35, 41, "-", 0xffffffff, 0xff000000, 0xc },
		{ 519, 87, 35, 41, "=", 0xffffffff, 0xff000000, 0xd },
		{ 559, 87, 53, 41, "Back", 0xffabb2bb, 0xff000000, 0xe },
		{ 39, 136, 53, 41, "Tab", 0xffabb2bb, 0xff000000, 0xf },
		{ 96, 136, 35, 41, "Q", 0xffffffff, 0xff000000, 0x10 },
		{ 136, 136, 35, 41, "W", 0xffffffff, 0xff000000, 0x11 },
		{ 176, 136, 35, 41, "E", 0xffffffff, 0xff000000, 0x12 },
		{ 216, 136, 35, 41, "R", 0xffffffff, 0xff000000, 0x13 },
		{ 256, 136, 35, 41, "T", 0xffffffff, 0xff000000, 0x14 },
		{ 296, 136, 35, 41, "Y", 0xffffffff, 0xff000000, 0x15 },
		{ 336, 136, 35, 41, "U", 0xffffffff, 0xff000000, 0x16 },
		{ 376, 136, 35, 41, "I", 0xffffffff, 0xff000000, 0x17 },
		{ 416, 136, 35, 41, "O", 0xffffffff, 0xff000000, 0x18 },
		{ 456, 136, 35, 41, "P", 0xffffffff, 0xff000000, 0x19 },
		{ 496, 136, 35, 41, "[", 0xffffffff, 0xff000000, 0x1a },
		{ 536, 136, 35, 41, "]", 0xffffffff, 0xff000000, 0x1b },
		{ 576, 136, 35, 41, "\\", 0xffffffff, 0xff000000, 0x2b },
		{ 50, 185, 53, 41, "Caps", 0xffabb2bb, 0xff000000, 0x3a },
		{ 108, 185, 35, 41, "A", 0xffffffff, 0xff000000, 0x1e },
		{ 148, 185, 35, 41, "S", 0xffffffff, 0xff000000, 0x1f },
		{ 188, 185, 35, 41, "D", 0xffffffff, 0xff000000, 0x20 },
		{ 228, 185, 35, 41, "F", 0xffffffff, 0xff000000, 0x21 },
		{ 268, 185, 35, 41, "G", 0xffffffff, 0xff000000, 0x22 },
		{ 308, 185, 35, 41, "H", 0xffffffff, 0xff000000, 0x23 },
		{ 348, 185, 35, 41, "J", 0xffffffff, 0xff000000, 0x24 },
		{ 388, 185, 35, 41, "K", 0xffffffff, 0xff000000, 0x25 },
		{ 428, 185, 35, 41, "L", 0xffffffff, 0xff000000, 0x26 },
		{ 468, 185, 35, 41, ";", 0xffffffff, 0xff000000, 0x27 },
		{ 508, 185, 35, 41, "'", 0xffffffff, 0xff000000, 0x28 },
		{ 548, 185, 53, 41, "Enter", 0xffabb2bb, 0xff000000, 0x1c },
		{ 13, 234, 53, 41, "Win", 0xffabb2bb, 0xff000000, 0xe05b },
		{ 70, 234, 53, 41, "Shift", 0xffabb2bb, 0xff000000, 0x2a },
		{ 128, 234, 35, 41, "Z", 0xffffffff, 0xff000000, 0x2c },
		{ 168, 234, 35, 41, "X", 0xffffffff, 0xff000000, 0x2d },
		{ 208, 234, 35, 41, "C", 0xffffffff, 0xff000000, 0x2e },
		{ 248, 234, 35, 41, "V", 0xffffffff, 0xff000000, 0x2f },
		{ 288, 234, 35, 41, "B", 0xffffffff, 0xff000000, 0x30 },
		{ 328, 234, 35, 41, "N", 0xffffffff, 0xff000000, 0x31 },
		{ 368, 234, 35, 41, "M", 0xffffffff, 0xff000000, 0x32 },
		{ 408, 234, 35, 41, ",", 0xffffffff, 0xff000000, 0x33 },
		{ 448, 234, 35, 41, ".", 0xffffffff, 0xff000000, 0x34 },
		{ 488, 234, 35, 41, "/", 0xffffffff, 0xff000000, 0x35 },
		{ 528, 234, 53, 41, "Up", 0xffabb2bb, 0xff000000, 0xe048 },
		{ 585, 234, 53, 41, "Menu", 0xffabb2bb, 0xff000000, 0xe05d },
		{ 13, 283, 53, 41, "Ctrl", 0xffabb2bb, 0xff000000, 0x1d },
		{ 70, 283, 53, 41, "Alt", 0xffabb2bb, 0xff000000, 0x38 },
		{ 128, 283, 280, 41, "Space", 0xffffffff, 0xff000000, 0x39 },
		{ 413, 283, 53, 41, "Del", 0xffabb2bb, 0xff000000, 0xe053 },
		{ 470, 283, 53, 41, "Left", 0xffabb2bb, 0xff000000, 0xe04b },
		{ 528, 283, 53, 41, "Down", 0xffabb2bb, 0xff000000, 0xe050 },
		{ 585, 283, 53, 41, "Right", 0xffabb2bb, 0xff000000, 0xe04d },
		{ 0, 0, 0, 0, NULL, 0, 0 }
	}
};
#define VKBDLAYOUT_LEN 78
#define VKBDLAYOUT_W 650
#define VKBDLAYOUT_H 334

