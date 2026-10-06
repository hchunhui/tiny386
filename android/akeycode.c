#define ANDROID_KEYCODES_MAX 200

static const int akeycode_to_linux_array[ANDROID_KEYCODES_MAX] = {
	[7]  = 0x0b, // AKEYCODE_0                -> KEY_0 (11)
	[8]  = 0x02, // AKEYCODE_1                -> KEY_1 (2)
	[9]  = 0x03, // AKEYCODE_2                -> KEY_2 (3)
	[10] = 0x04, // AKEYCODE_3                -> KEY_3 (4)
	[11] = 0x05, // AKEYCODE_4                -> KEY_4 (5)
	[12] = 0x06, // AKEYCODE_5                -> KEY_5 (6)
	[13] = 0x07, // AKEYCODE_6                -> KEY_6 (7)
	[14] = 0x08, // AKEYCODE_7                -> KEY_7 (8)
	[15] = 0x09, // AKEYCODE_8                -> KEY_8 (9)
	[16] = 0x0a, // AKEYCODE_9                -> KEY_9 (10)

	[29] = 0x1e, // AKEYCODE_A                -> KEY_A (30)
	[30] = 0x30, // AKEYCODE_B                -> KEY_B (48)
	[31] = 0x2e, // AKEYCODE_C                -> KEY_C (46)
	[32] = 0x20, // AKEYCODE_D                -> KEY_D (32)
	[33] = 0x12, // AKEYCODE_E                -> KEY_E (18)
	[34] = 0x21, // AKEYCODE_F                -> KEY_F (33)
	[35] = 0x22, // AKEYCODE_G                -> KEY_G (34)
	[36] = 0x23, // AKEYCODE_H                -> KEY_H (35)
	[37] = 0x17, // AKEYCODE_I                -> KEY_I (23)
	[38] = 0x24, // AKEYCODE_J                -> KEY_J (36)
	[39] = 0x25, // AKEYCODE_K                -> KEY_K (37)
	[40] = 0x26, // AKEYCODE_L                -> KEY_L (38)
	[41] = 0x32, // AKEYCODE_M                -> KEY_M (50)
	[42] = 0x31, // AKEYCODE_N                -> KEY_N (49)
	[43] = 0x18, // AKEYCODE_O                -> KEY_O (24)
	[44] = 0x19, // AKEYCODE_P                -> KEY_P (25)
	[45] = 0x10, // AKEYCODE_Q                -> KEY_Q (16)
	[46] = 0x13, // AKEYCODE_R                -> KEY_R (19)
	[47] = 0x1f, // AKEYCODE_S                -> KEY_S (31)
	[48] = 0x14, // AKEYCODE_T                -> KEY_T (20)
	[49] = 0x16, // AKEYCODE_U                -> KEY_U (22)
	[50] = 0x2f, // AKEYCODE_V                -> KEY_V (47)
	[51] = 0x11, // AKEYCODE_W                -> KEY_W (17)
	[52] = 0x2d, // AKEYCODE_X                -> KEY_X (45)
	[53] = 0x15, // AKEYCODE_Y                -> KEY_Y (21)
	[54] = 0x2c, // AKEYCODE_Z                -> KEY_Z (44)

	[111] = 0x01, // AKEYCODE_ESCAPE          -> KEY_ESC (1)
	[61]  = 0x0f, // AKEYCODE_TAB             -> KEY_TAB (15)
	[62]  = 0x39, // AKEYCODE_SPACE           -> KEY_SPACE (57)
	[66]  = 0x1c, // AKEYCODE_ENTER           -> KEY_ENTER (28)
	[67]  = 0x0e, // AKEYCODE_DEL             -> KEY_BACKSPACE (14)
	[68]  = 0x29, // AKEYCODE_GRAVE           -> KEY_GRAVE (41)  [ ~ ` ]
	[69]  = 0x0c, // AKEYCODE_MINUS           -> KEY_MINUS (12)  [ - _ ]
	[70]  = 0x0d, // AKEYCODE_EQUALS          -> KEY_EQUAL (13)  [ = + ]
	[71]  = 0x1a, // AKEYCODE_LEFT_BRACKET    -> KEY_LEFTBRACE (26)  [ [ { ]
	[72]  = 0x1b, // AKEYCODE_RIGHT_BRACKET   -> KEY_RIGHTBRACE (27) [ ] } ]
	[73]  = 0x2b, // AKEYCODE_BACKSLASH       -> KEY_BACKSLASH (43)  [ \ | ]
	[74]  = 0x27, // AKEYCODE_SEMICOLON       -> KEY_SEMICOLON (39)  [ ; : ]
	[75]  = 0x28, // AKEYCODE_APOSTROPHE      -> KEY_APOSTROPHE (40) [ ' " ]
	[55]  = 0x33, // AKEYCODE_COMMA           -> KEY_COMMA (51)  [ , < ]
	[56]  = 0x34, // AKEYCODE_PERIOD          -> KEY_PERIOD (52) [ . > ]
	[76]  = 0x35, // AKEYCODE_SLASH           -> KEY_SLASH (53)  [ / ? ]

	[57]  = 0x38, // AKEYCODE_ALT_LEFT        -> KEY_LEFTALT (56)
	[58]  = 0x64, // AKEYCODE_ALT_RIGHT       -> KEY_RIGHTALT (100)
	[59]  = 0x2a, // AKEYCODE_SHIFT_LEFT      -> KEY_LEFTSHIFT (42)
	[60]  = 0x36, // AKEYCODE_SHIFT_RIGHT     -> KEY_RIGHTSHIFT (54)
	[113] = 0x1d, // AKEYCODE_CTRL_LEFT       -> KEY_LEFTCTRL (29)
	[114] = 0x61, // AKEYCODE_CTRL_RIGHT      -> KEY_RIGHTCTRL (97)
	[115] = 0x3a, // AKEYCODE_CAPS_LOCK       -> KEY_CAPSLOCK (58)
	[117] = 0x7d, // AKEYCODE_META_LEFT       -> KEY_LEFTMETA (125)
	[118] = 0x7e, // AKEYCODE_META_RIGHT      -> KEY_RIGHTMETA (126)
	[82]  = 0x8b, // AKEYCODE_MENU            -> KEY_MENU (139)

	[131] = 0x3b, // AKEYCODE_F1              -> KEY_F1 (59)
	[132] = 0x3c, // AKEYCODE_F2              -> KEY_F2 (60)
	[133] = 0x3d, // AKEYCODE_F3              -> KEY_F3 (61)
	[134] = 0x3e, // AKEYCODE_F4              -> KEY_F4 (62)
	[135] = 0x3f, // AKEYCODE_F5              -> KEY_F5 (63)
	[136] = 0x40, // AKEYCODE_F6              -> KEY_F6 (64)
	[137] = 0x41, // AKEYCODE_F7              -> KEY_F7 (65)
	[138] = 0x42, // AKEYCODE_F8              -> KEY_F8 (66)
	[139] = 0x43, // AKEYCODE_F9              -> KEY_F9 (67)
	[140] = 0x44, // AKEYCODE_F10             -> KEY_F10 (68)
	[141] = 0x57, // AKEYCODE_F11             -> KEY_F11 (87)
	[142] = 0x58, // AKEYCODE_F12             -> KEY_F12 (88)

	[19]  = 0x67, // AKEYCODE_DPAD_UP         -> KEY_UP (103)
	[20]  = 0x6c, // AKEYCODE_DPAD_DOWN       -> KEY_DOWN (108)
	[21]  = 0x69, // AKEYCODE_DPAD_LEFT       -> KEY_LEFT (105)
	[22]  = 0x6a, // AKEYCODE_DPAD_RIGHT      -> KEY_RIGHT (106)

	[124] = 0x6e, // AKEYCODE_INSERT          -> KEY_INSERT (110)
	[112] = 0x6f, // AKEYCODE_FORWARD_DEL     -> KEY_DELETE (111)
	[122] = 0x66, // AKEYCODE_MOVE_HOME       -> KEY_HOME (102)
	[123] = 0x6b, // AKEYCODE_MOVE_END        -> KEY_END (107)
	[92]  = 0x68, // AKEYCODE_PAGE_UP         -> KEY_PAGEUP (104)
	[93]  = 0x6d, // AKEYCODE_PAGEDOWN        -> KEY_PAGEDOWN (109)

	[120] = 0x63, // AKEYCODE_SYSRQ           -> KEY_SYSRQ (99)
	[116] = 0x46, // AKEYCODE_SCROLL_LOCK     -> KEY_SCROLLLOCK (70)
	[121] = 0x77, // AKEYCODE_BREAK           -> KEY_PAUSE (119)

	[143] = 0x45, // AKEYCODE_NUM_LOCK        -> KEY_NUMLOCK (69)
	[144] = 0x52, // AKEYCODE_NUMPAD_0        -> KEY_KP0 (82)
	[145] = 0x4f, // AKEYCODE_NUMPAD_1        -> KEY_KP1 (79)
	[146] = 0x50, // AKEYCODE_NUMPAD_2        -> KEY_KP2 (80)
	[147] = 0x51, // AKEYCODE_NUMPAD_3        -> KEY_KP3 (81)
	[148] = 0x4b, // AKEYCODE_NUMPAD_4        -> KEY_KP4 (75)
	[149] = 0x4c, // AKEYCODE_NUMPAD_5        -> KEY_KP5 (76)
	[150] = 0x4d, // AKEYCODE_NUMPAD_6        -> KEY_KP6 (77)
	[151] = 0x47, // AKEYCODE_NUMPAD_7        -> KEY_KP7 (71)
	[152] = 0x48, // AKEYCODE_NUMPAD_8        -> KEY_KP8 (72)
	[153] = 0x49, // AKEYCODE_NUMPAD_9        -> KEY_KP9 (73)
	[154] = 0x62, // AKEYCODE_NUMPAD_DIVIDE    -> KEY_KPSLASH (98)  [ / ]
	[155] = 0x37, // AKEYCODE_NUMPAD_MULTIPLY  -> KEY_KPASTERISK (55) [ * ]
	[156] = 0x4a, // AKEYCODE_NUMPAD_SUBTRACT  -> KEY_KPMINUS (74)   [ - ]
	[157] = 0x4e, // AKEYCODE_NUMPAD_ADD       -> KEY_KPPLUS (78)    [ + ]
	[158] = 0x53, // AKEYCODE_NUMPAD_DOT       -> KEY_KPDOT (83)     [ . ]
	[160] = 0x60, // AKEYCODE_NUMPAD_ENTER     -> KEY_KPENTER (96)
};

int akeycode_to_linux(int akeycode) {
	if (akeycode < 0 || akeycode >= ANDROID_KEYCODES_MAX) {
		return 0;
	}
	return akeycode_to_linux_array[akeycode];
}
