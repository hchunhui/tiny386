#include <stdint.h>

const char *hid_usage_to_name(uint8_t code)
{
    switch (code) {

    case 0x00: return "NONE";
    case 0x01: return "ERR_OVF";

    // Letters
    case 0x04: return "A";
    case 0x05: return "B";
    case 0x06: return "C";
    case 0x07: return "D";
    case 0x08: return "E";
    case 0x09: return "F";
    case 0x0A: return "G";
    case 0x0B: return "H";
    case 0x0C: return "I";
    case 0x0D: return "J";
    case 0x0E: return "K";
    case 0x0F: return "L";
    case 0x10: return "M";
    case 0x11: return "N";
    case 0x12: return "O";
    case 0x13: return "P";
    case 0x14: return "Q";
    case 0x15: return "R";
    case 0x16: return "S";
    case 0x17: return "T";
    case 0x18: return "U";
    case 0x19: return "V";
    case 0x1A: return "W";
    case 0x1B: return "X";
    case 0x1C: return "Y";
    case 0x1D: return "Z";

    // Numbers
    case 0x1E: return "1";
    case 0x1F: return "2";
    case 0x20: return "3";
    case 0x21: return "4";
    case 0x22: return "5";
    case 0x23: return "6";
    case 0x24: return "7";
    case 0x25: return "8";
    case 0x26: return "9";
    case 0x27: return "0";

    // Controls
    case 0x28: return "ENTER";
    case 0x29: return "ESC";
    case 0x2A: return "BACKSPACE";
    case 0x2B: return "TAB";
    case 0x2C: return "SPACE";
    case 0x2D: return "-";
    case 0x2E: return "=";
    case 0x2F: return "[";
    case 0x30: return "]";
    case 0x31: return "\\";
    case 0x32: return "NONUS#";
    case 0x33: return ";";
    case 0x34: return "'";
    case 0x35: return "`";
    case 0x36: return ",";
    case 0x37: return ".";
    case 0x38: return "/";
    case 0x39: return "CAPSLOCK";

    // Function keys
    case 0x3A: return "F1";
    case 0x3B: return "F2";
    case 0x3C: return "F3";
    case 0x3D: return "F4";
    case 0x3E: return "F5";
    case 0x3F: return "F6";
    case 0x40: return "F7";
    case 0x41: return "F8";
    case 0x42: return "F9";
    case 0x43: return "F10";
    case 0x44: return "F11";
    case 0x45: return "F12";

    // Navigation
    case 0x46: return "PRINTSCREEN";
    case 0x47: return "SCROLLLOCK";
    case 0x48: return "PAUSE";
    case 0x49: return "INSERT";
    case 0x4A: return "HOME";
    case 0x4B: return "PAGEUP";
    case 0x4C: return "DELETE";
    case 0x4D: return "END";
    case 0x4E: return "PAGEDOWN";
    case 0x4F: return "RIGHT";
    case 0x50: return "LEFT";
    case 0x51: return "DOWN";
    case 0x52: return "UP";

    // Keypad
    case 0x53: return "NUMLOCK";
    case 0x54: return "KP /";
    case 0x55: return "KP *";
    case 0x56: return "KP -";
    case 0x57: return "KP +";
    case 0x58: return "KP ENTER";
    case 0x59: return "KP 1";
    case 0x5A: return "KP 2";
    case 0x5B: return "KP 3";
    case 0x5C: return "KP 4";
    case 0x5D: return "KP 5";
    case 0x5E: return "KP 6";
    case 0x5F: return "KP 7";
    case 0x60: return "KP 8";
    case 0x61: return "KP 9";
    case 0x62: return "KP 0";
    case 0x63: return "KP .";

    case 0x64: return "NONUSBACKSLASH";
    case 0x65: return "APPLICATION";

    // Modifiers (as keycodes)
    case 0xE0: return "LEFTCTRL";
    case 0xE1: return "LEFTSHIFT";
    case 0xE2: return "LEFTALT";
    case 0xE3: return "LEFTMETA";
    case 0xE4: return "RIGHTCTRL";
    case 0xE5: return "RIGHTSHIFT";
    case 0xE6: return "RIGHTALT";
    case 0xE7: return "RIGHTMETA";

    default: return "UNKNOWN";
    }
}


int hid_usage_to_ps2input(int hid)
{
    switch (hid)
    {
        /* -----------------------------------------------------------
         * 0x00–0x03: NONE / ERRORS
         * ----------------------------------------------------------- */
        case 0x00: return 0;    // No event
        case 0x01: return 0;    // Rollover
        case 0x02: return 0;
        case 0x03: return 0;

        /* -----------------------------------------------------------
         * Letters (A–Z)
         * ----------------------------------------------------------- */
        case 0x04: return 30;  // A
        case 0x05: return 48;  // B
        case 0x06: return 46;  // C
        case 0x07: return 32;  // D
        case 0x08: return 18;  // E
        case 0x09: return 33;  // F
        case 0x0A: return 34;  // G
        case 0x0B: return 35;  // H
        case 0x0C: return 23;  // I
        case 0x0D: return 36;  // J
        case 0x0E: return 37;  // K
        case 0x0F: return 38;  // L
        case 0x10: return 50;  // M
        case 0x11: return 49;  // N
        case 0x12: return 24;  // O
        case 0x13: return 25;  // P
        case 0x14: return 16;  // Q
        case 0x15: return 19;  // R
        case 0x16: return 31;  // S
        case 0x17: return 20;  // T
        case 0x18: return 22;  // U
        case 0x19: return 47;  // V
        case 0x1A: return 17;  // W
        case 0x1B: return 45;  // X
        case 0x1C: return 21;  // Y
        case 0x1D: return 44;  // Z

        /* -----------------------------------------------------------
         * Numbers (1–0)
         * ----------------------------------------------------------- */
        case 0x1E: return 2;
        case 0x1F: return 3;
        case 0x20: return 4;
        case 0x21: return 5;
        case 0x22: return 6;
        case 0x23: return 7;
        case 0x24: return 8;
        case 0x25: return 9;
        case 0x26: return 10;
        case 0x27: return 11;

        /* -----------------------------------------------------------
         * Basic punctuation & controls
         * ----------------------------------------------------------- */
        case 0x28: return 28;  // Enter
        case 0x29: return 1;   // Esc
        case 0x2A: return 14;  // Backspace
        case 0x2B: return 15;  // Tab
        case 0x2C: return 57;  // Space
        case 0x2D: return 12;  // -
        case 0x2E: return 13;  // =
        case 0x2F: return 26;  // [
        case 0x30: return 27;  // ]
        case 0x31: return 43;  // Backslash
        case 0x32: return 86;  // NON-US # ~ (ISO)
        case 0x33: return 39;  // ;
        case 0x34: return 40;  // '
        case 0x35: return 41;  // `
        case 0x36: return 51;  // ,
        case 0x37: return 52;  // .
        case 0x38: return 53;  // /
        case 0x39: return 58;  // Caps Lock

        /* -----------------------------------------------------------
         * Function keys F1–F12
         * ----------------------------------------------------------- */
        case 0x3A: return 59;  // F1
        case 0x3B: return 60;  // F2
        case 0x3C: return 61;  // F3
        case 0x3D: return 62;  // F4
        case 0x3E: return 63;  // F5
        case 0x3F: return 64;  // F6
        case 0x40: return 65;  // F7
        case 0x41: return 66;  // F8
        case 0x42: return 67;  // F9
        case 0x43: return 68;  // F10
        case 0x44: return 87;  // F11
        case 0x45: return 88;  // F12

        /* -----------------------------------------------------------
         * PrintScreen / ScrollLock / Pause (weird keys)
         * ----------------------------------------------------------- */
        case 0x46: return 0xE037; // PrintScreen (E0 37)
        case 0x47: return 70;     // Scroll Lock
        case 0x48: return 0xE046; // Pause/Break (E0 46)

        /* -----------------------------------------------------------
         * Navigation keys (ALL EXTENDED)
         * ----------------------------------------------------------- */
        case 0x49: return 0xE070; // Insert
        case 0x4A: return 0xE06C; // Home
        case 0x4B: return 0xE07D; // PageUp
        case 0x4C: return 0xE071; // Delete
        case 0x4D: return 0xE069; // End
        case 0x4E: return 0xE07A; // PageDown

        case 0x4F: return 0xE074; // Right
        case 0x50: return 0xE06B; // Left
        case 0x51: return 0xE072; // Down
        case 0x52: return 0xE075; // Up

        /* -----------------------------------------------------------
         * Keypad
         * ----------------------------------------------------------- */
        case 0x53: return 69;     // Num Lock
        case 0x54: return 98;     // Keypad /
        case 0x55: return 55;     // Keypad *
        case 0x56: return 74;     // Keypad -
        case 0x57: return 78;     // Keypad +
        case 0x58: return 96;     // Keypad Enter (extended)
        case 0x59: return 79;
        case 0x5A: return 80;
        case 0x5B: return 81;
        case 0x5C: return 75;
        case 0x5D: return 76;
        case 0x5E: return 77;
        case 0x5F: return 71;
        case 0x60: return 72;
        case 0x61: return 73;
        case 0x62: return 82;
        case 0x63: return 83;

        /* -----------------------------------------------------------
         * APPLICATION / MENU
         * ----------------------------------------------------------- */
        case 0x65: return 93; // Menu key

        /* -----------------------------------------------------------
         * Modifiers (USB HID → Linux Input)
         * ----------------------------------------------------------- */
        case 0xE0: return 29;     // Left Ctrl
        case 0xE1: return 42;     // Left Shift
        case 0xE2: return 56;     // Left Alt
        case 0xE3: return 125;    // Left GUI
        case 0xE4: return 97;     // Right Ctrl
        case 0xE5: return 54;     // Right Shift
        case 0xE6: return 100;    // Right Alt
        case 0xE7: return 126;    // Right GUI

        /* -----------------------------------------------------------
         * Unsupported / not present on PS/2
         * ----------------------------------------------------------- */
        default:
            return 0;
    }
}

int hid_usage_to_linux_keycode(int hid)
{
    switch (hid)
    {
        /* -----------------------------------------------------------
         * 0x00–0x03: NONE / ERRORS
         * ----------------------------------------------------------- */
        case 0x00: return 0;
        case 0x01: return 0;
        case 0x02: return 0;
        case 0x03: return 0;

        /* -----------------------------------------------------------
         * Letters (USB HID → Linux KEY_*)
         * ----------------------------------------------------------- */
        case 0x04: return 30;  // KEY_A
        case 0x05: return 48;  // KEY_B
        case 0x06: return 46;  // KEY_C
        case 0x07: return 32;  // KEY_D
        case 0x08: return 18;  // KEY_E
        case 0x09: return 33;  // KEY_F
        case 0x0A: return 34;  // KEY_G
        case 0x0B: return 35;  // KEY_H
        case 0x0C: return 23;  // KEY_I
        case 0x0D: return 36;  // KEY_J
        case 0x0E: return 37;  // KEY_K
        case 0x0F: return 38;  // KEY_L
        case 0x10: return 50;  // KEY_M
        case 0x11: return 49;  // KEY_N
        case 0x12: return 24;  // KEY_O
        case 0x13: return 25;  // KEY_P
        case 0x14: return 16;  // KEY_Q
        case 0x15: return 19;  // KEY_R
        case 0x16: return 31;  // KEY_S
        case 0x17: return 20;  // KEY_T
        case 0x18: return 22;  // KEY_U
        case 0x19: return 47;  // KEY_V
        case 0x1A: return 17;  // KEY_W
        case 0x1B: return 45;  // KEY_X
        case 0x1C: return 21;  // KEY_Y
        case 0x1D: return 44;  // KEY_Z

        /* -----------------------------------------------------------
         * Numbers row
         * ----------------------------------------------------------- */
        case 0x1E: return 2;   // KEY_1
        case 0x1F: return 3;   // KEY_2
        case 0x20: return 4;
        case 0x21: return 5;
        case 0x22: return 6;
        case 0x23: return 7;
        case 0x24: return 8;
        case 0x25: return 9;
        case 0x26: return 10;
        case 0x27: return 11;  // KEY_0

        /* -----------------------------------------------------------
         * Controls & punctuation
         * ----------------------------------------------------------- */
        case 0x28: return 28;  // KEY_ENTER
        case 0x29: return 1;   // KEY_ESC
        case 0x2A: return 14;  // KEY_BACKSPACE
        case 0x2B: return 15;  // KEY_TAB
        case 0x2C: return 57;  // KEY_SPACE
        case 0x2D: return 12;  // KEY_MINUS
        case 0x2E: return 13;  // KEY_EQUAL
        case 0x2F: return 26;  // KEY_LEFTBRACE
        case 0x30: return 27;  // KEY_RIGHTBRACE
        case 0x31: return 43;  // KEY_BACKSLASH
        case 0x32: return 86;  // KEY_102ND (Non-US)
        case 0x33: return 39;  // KEY_SEMICOLON
        case 0x34: return 40;  // KEY_APOSTROPHE
        case 0x35: return 41;  // KEY_GRAVE
        case 0x36: return 51;  // KEY_COMMA
        case 0x37: return 52;  // KEY_DOT
        case 0x38: return 53;  // KEY_SLASH
        case 0x39: return 58;  // KEY_CAPSLOCK

        /* -----------------------------------------------------------
         * Function keys
         * ----------------------------------------------------------- */
        case 0x3A: return 59;  // KEY_F1
        case 0x3B: return 60;
        case 0x3C: return 61;
        case 0x3D: return 62;
        case 0x3E: return 63;
        case 0x3F: return 64;
        case 0x40: return 65;
        case 0x41: return 66;
        case 0x42: return 67;
        case 0x43: return 68;
        case 0x44: return 87;  // KEY_F11
        case 0x45: return 88;  // KEY_F12

        /* -----------------------------------------------------------
         * Navigation
         * ----------------------------------------------------------- */
        case 0x46: return 99;   // KEY_SYSRQ (Print Screen)
        case 0x47: return 70;   // KEY_SCROLLLOCK
        case 0x48: return 119;  // KEY_PAUSE

        case 0x49: return 110;  // KEY_INSERT
        case 0x4A: return 102;  // KEY_HOME
        case 0x4B: return 104;  // KEY_PAGEUP
        case 0x4C: return 111;  // KEY_DELETE
        case 0x4D: return 107;  // KEY_END
        case 0x4E: return 109;  // KEY_PAGEDOWN

        case 0x4F: return 106;  // KEY_RIGHT
        case 0x50: return 105;  // KEY_LEFT
        case 0x51: return 108;  // KEY_DOWN
        case 0x52: return 103;  // KEY_UP

        /* -----------------------------------------------------------
         * Keypad
         * ----------------------------------------------------------- */
        case 0x53: return 69;   // KEY_NUMLOCK
        case 0x54: return 98;   // KEY_KPSLASH
        case 0x55: return 55;   // KEY_KPASTERISK
        case 0x56: return 74;   // KEY_KPMINUS
        case 0x57: return 78;   // KEY_KPPLUS
        case 0x58: return 96;   // KEY_KPENTER
        case 0x59: return 79;
        case 0x5A: return 80;
        case 0x5B: return 81;
        case 0x5C: return 75;
        case 0x5D: return 76;
        case 0x5E: return 77;
        case 0x5F: return 71;
        case 0x60: return 72;
        case 0x61: return 73;
        case 0x62: return 82;
        case 0x63: return 83;

        /* -----------------------------------------------------------
         * Application / Menu key
         * ----------------------------------------------------------- */
        case 0x65: return 139;  // KEY_MENU

        /* -----------------------------------------------------------
         * Modifiers
         * ----------------------------------------------------------- */
        case 0xE0: return 29;   // KEY_LEFTCTRL
        case 0xE1: return 42;   // KEY_LEFTSHIFT
        case 0xE2: return 56;   // KEY_LEFTALT
        case 0xE3: return 125;  // KEY_LEFTMETA
        case 0xE4: return 97;   // KEY_RIGHTCTRL
        case 0xE5: return 54;   // KEY_RIGHTSHIFT
        case 0xE6: return 100;  // KEY_RIGHTALT
        case 0xE7: return 126;  // KEY_RIGHTMETA

        /* -----------------------------------------------------------
         * Unsupported
         * ----------------------------------------------------------- */
        default:
            return 0;
    }
}
