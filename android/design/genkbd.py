import sys
import json

j = json.loads(open(sys.argv[1]).read())
out = []
out.append('''
struct VKBDLayout {
\tuint32_t color;
\tstruct {
\t\tint x, y, w, h;
\t\tconst char *text;
\t\tuint32_t bgcolor, fgcolor;
\t\tint code;
\t} items[];
};

const static struct VKBDLayout vkbd_layout = {
''')

key2code = {
    "Esc": 0x0001,
    "1": 0x0002, "2": 0x0003, "3": 0x0004, "4": 0x0005, "5": 0x0006,
    "6": 0x0007, "7": 0x0008, "8": 0x0009, "9": 0x000a, "0": 0x000b,
    "-": 0x000c, "=": 0x000d, "Back": 0x000e, "Tab": 0x000f,
    "Q": 0x0010, "W": 0x0011, "E": 0x0012, "R": 0x0013, "T": 0x0014,
    "Y": 0x0015, "U": 0x0016, "I": 0x0017, "O": 0x0018, "P": 0x0019,
    "[": 0x001a, "]": 0x001b, "Enter": 0x001c, "Ctrl": 0x001d,
    "A": 0x001e, "S": 0x001f, "D": 0x0020, "F": 0x0021, "G": 0x0022,
    "H": 0x0023, "J": 0x0024, "K": 0x0025, "L": 0x0026, ";": 0x0027,
    "'": 0x0028, "`": 0x0029, "Shift": 0x002a, "\\": 0x002b,
    "Z": 0x002c, "X": 0x002d, "C": 0x002e, "V": 0x002f, "B": 0x0030,
    "N": 0x0031, "M": 0x0032, ",": 0x0033, ".": 0x0034, "/": 0x0035,
    "Alt": 0x0038, "Space": 0x0039, "Caps": 0x003a,
    "F1": 0x003b, "F2": 0x003c, "F3": 0x003d, "F4": 0x003e, "F5": 0x003f,
    "F6": 0x0040, "F7": 0x0041, "F8": 0x0042, "F9": 0x0043, "F10": 0x0044,
    "F11": 0x0057, "F12": 0x0058,
    "Home": 0xe047, "Up": 0xe048, "PgUp": 0xe049, "Left": 0xe04b,
    "Right": 0xe04d, "End": 0xe04f, "Down": 0xe050, "PgDn": 0xe051,
    "Insert": 0xe052, "Del": 0xe053,
    "Win": 0xe05b, "Menu": 0xe05d,
    "---": -1,
}

out.append('\t{},\n'.format(j[0]['backgroundColor']))
out.append('\t{\n');
slen = 0
for i in j[1:]:
    if (int(i['backgroundColor'], 0) >> 24) != 0:
        slen += 1
        out.append('\t\t{} {}, {}, {}, {}, {}, {}, {}, {} {},\n'.format(
            '{',
            i['left'], i['top'], i['width'], i['height'], json.dumps(i['text']),
            i['backgroundColor'], i['color'], hex(key2code.get(i['text'], 0)),
            '}'))
out.append('\t\t{ 0, 0, 0, 0, NULL, 0, 0 }\n')
out.append('\t}\n');
out.append('};\n')
out.append('#define VKBDLAYOUT_LEN {}\n'.format(slen))
out.append('#define VKBDLAYOUT_W {}\n'.format(j[0]['width']))
out.append('#define VKBDLAYOUT_H {}\n'.format(j[0]['height']))
print(''.join(out))
