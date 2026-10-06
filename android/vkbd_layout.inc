
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
		{ 1, 1, 559, 25, "---", 0xffabb2bb, 0xffffffff, -0x1 },
		{ 4, 27, 35, 41, "Esc", 0xffabb2bb, 0xff000000, 0x1 },
		{ 41, 27, 35, 41, "F1", 0xffabb2bb, 0xff000000, 0x3b },
		{ 78, 27, 35, 41, "F2", 0xffabb2bb, 0xff000000, 0x3c },
		{ 115, 27, 35, 41, "F3", 0xffabb2bb, 0xff000000, 0x3d },
		{ 152, 27, 35, 41, "F4", 0xffabb2bb, 0xff000000, 0x3e },
		{ 189, 27, 35, 41, "F5", 0xffabb2bb, 0xff000000, 0x3f },
		{ 226, 27, 35, 41, "F6", 0xffabb2bb, 0xff000000, 0x40 },
		{ 263, 27, 35, 41, "F7", 0xffabb2bb, 0xff000000, 0x41 },
		{ 300, 27, 35, 41, "F8", 0xffabb2bb, 0xff000000, 0x42 },
		{ 337, 27, 35, 41, "F9", 0xffabb2bb, 0xff000000, 0x43 },
		{ 374, 27, 35, 41, "F10", 0xffabb2bb, 0xff000000, 0x44 },
		{ 411, 27, 35, 41, "F11", 0xffabb2bb, 0xff000000, 0x57 },
		{ 448, 27, 35, 41, "F12", 0xffabb2bb, 0xff000000, 0x58 },
		{ 485, 27, 35, 41, "PgUp", 0xffabb2bb, 0xff000000, 0xe049 },
		{ 522, 27, 35, 41, "PgDn", 0xffabb2bb, 0xff000000, 0xe051 },
		{ 18, 70, 35, 41, "`", 0xffffffff, 0xff000000, 0x29 },
		{ 55, 70, 35, 41, "1", 0xffffffff, 0xff000000, 0x2 },
		{ 92, 70, 35, 41, "2", 0xffffffff, 0xff000000, 0x3 },
		{ 129, 70, 35, 41, "3", 0xffffffff, 0xff000000, 0x4 },
		{ 166, 70, 35, 41, "4", 0xffffffff, 0xff000000, 0x5 },
		{ 203, 70, 35, 41, "5", 0xffffffff, 0xff000000, 0x6 },
		{ 240, 70, 35, 41, "6", 0xffffffff, 0xff000000, 0x7 },
		{ 277, 70, 35, 41, "7", 0xffffffff, 0xff000000, 0x8 },
		{ 314, 70, 35, 41, "8", 0xffffffff, 0xff000000, 0x9 },
		{ 351, 70, 35, 41, "9", 0xffffffff, 0xff000000, 0xa },
		{ 388, 70, 35, 41, "0", 0xffffffff, 0xff000000, 0xb },
		{ 425, 70, 35, 41, "-", 0xffffffff, 0xff000000, 0xc },
		{ 462, 70, 35, 41, "=", 0xffffffff, 0xff000000, 0xd },
		{ 499, 70, 45, 41, "Back", 0xffabb2bb, 0xff000000, 0xe },
		{ 18, 113, 45, 41, "Tab", 0xffabb2bb, 0xff000000, 0xf },
		{ 65, 113, 35, 41, "Q", 0xffffffff, 0xff000000, 0x10 },
		{ 102, 113, 35, 41, "W", 0xffffffff, 0xff000000, 0x11 },
		{ 139, 113, 35, 41, "E", 0xffffffff, 0xff000000, 0x12 },
		{ 176, 113, 35, 41, "R", 0xffffffff, 0xff000000, 0x13 },
		{ 213, 113, 35, 41, "T", 0xffffffff, 0xff000000, 0x14 },
		{ 250, 113, 35, 41, "Y", 0xffffffff, 0xff000000, 0x15 },
		{ 287, 113, 35, 41, "U", 0xffffffff, 0xff000000, 0x16 },
		{ 324, 113, 35, 41, "I", 0xffffffff, 0xff000000, 0x17 },
		{ 361, 113, 35, 41, "O", 0xffffffff, 0xff000000, 0x18 },
		{ 398, 113, 35, 41, "P", 0xffffffff, 0xff000000, 0x19 },
		{ 435, 113, 35, 41, "[", 0xffffffff, 0xff000000, 0x1a },
		{ 472, 113, 35, 41, "]", 0xffffffff, 0xff000000, 0x1b },
		{ 509, 113, 35, 41, "\\", 0xffffffff, 0xff000000, 0x2b },
		{ 31, 156, 45, 41, "Caps", 0xffabb2bb, 0xff000000, 0x3a },
		{ 78, 156, 35, 41, "A", 0xffffffff, 0xff000000, 0x1e },
		{ 115, 156, 35, 41, "S", 0xffffffff, 0xff000000, 0x1f },
		{ 152, 156, 35, 41, "D", 0xffffffff, 0xff000000, 0x20 },
		{ 189, 156, 35, 41, "F", 0xffffffff, 0xff000000, 0x21 },
		{ 226, 156, 35, 41, "G", 0xffffffff, 0xff000000, 0x22 },
		{ 263, 156, 35, 41, "H", 0xffffffff, 0xff000000, 0x23 },
		{ 300, 156, 35, 41, "J", 0xffffffff, 0xff000000, 0x24 },
		{ 337, 156, 35, 41, "K", 0xffffffff, 0xff000000, 0x25 },
		{ 374, 156, 35, 41, "L", 0xffffffff, 0xff000000, 0x26 },
		{ 411, 156, 35, 41, ";", 0xffffffff, 0xff000000, 0x27 },
		{ 448, 156, 35, 41, "'", 0xffffffff, 0xff000000, 0x28 },
		{ 485, 156, 45, 41, "Enter", 0xffabb2bb, 0xff000000, 0x1c },
		{ 3, 199, 45, 41, "Win", 0xffabb2bb, 0xff000000, 0xe05b },
		{ 50, 199, 45, 41, "Shift", 0xffabb2bb, 0xff000000, 0x2a },
		{ 97, 199, 35, 41, "Z", 0xffffffff, 0xff000000, 0x2c },
		{ 134, 199, 35, 41, "X", 0xffffffff, 0xff000000, 0x2d },
		{ 171, 199, 35, 41, "C", 0xffffffff, 0xff000000, 0x2e },
		{ 208, 199, 35, 41, "V", 0xffffffff, 0xff000000, 0x2f },
		{ 245, 199, 35, 41, "B", 0xffffffff, 0xff000000, 0x30 },
		{ 282, 199, 35, 41, "N", 0xffffffff, 0xff000000, 0x31 },
		{ 319, 199, 35, 41, "M", 0xffffffff, 0xff000000, 0x32 },
		{ 356, 199, 35, 41, ",", 0xffffffff, 0xff000000, 0x33 },
		{ 393, 199, 35, 41, ".", 0xffffffff, 0xff000000, 0x34 },
		{ 430, 199, 35, 41, "/", 0xffffffff, 0xff000000, 0x35 },
		{ 467, 199, 45, 41, "Up", 0xffabb2bb, 0xff000000, 0xe048 },
		{ 514, 199, 45, 41, "Shift", 0xffabb2bb, 0xff000000, 0x2a },
		{ 2, 242, 45, 41, "Ctrl", 0xffabb2bb, 0xff000000, 0x1d },
		{ 49, 242, 45, 41, "Alt", 0xffabb2bb, 0xff000000, 0x38 },
		{ 96, 242, 275, 41, "Space", 0xffffffff, 0xff000000, 0x39 },
		{ 373, 242, 45, 41, "Del", 0xffabb2bb, 0xff000000, 0xe053 },
		{ 420, 242, 45, 41, "Left", 0xffabb2bb, 0xff000000, 0xe04b },
		{ 467, 242, 45, 41, "Down", 0xffabb2bb, 0xff000000, 0xe050 },
		{ 514, 242, 45, 41, "Right", 0xffabb2bb, 0xff000000, 0xe04d },
		{ 0, 0, 0, 0, NULL, 0, 0 }
	}
};
#define VKBDLAYOUT_LEN 78
#define VKBDLAYOUT_W 561
#define VKBDLAYOUT_H 285

