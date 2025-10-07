'use strict';

let mem8;

function get_string(ptr)
{
    let len;
    for (len = 0; mem8[ptr + len]; len++);
    return new TextDecoder("utf-8").decode(mem8.slice(ptr, ptr + len));
}

function __abort(strptr)
{
    throw new Error('wasm abort: ' + get_string(strptr));
}

function exit(status)
{
    throw new Error('wasm exit with ' + status);
}

function __get_mticks()
{
    return Date.now();
}

function dolog(s)
{
    const o = document.getElementById('logarea');
    const len = o.value.length;
    if (len > 40960)
        o.value = o.value.substring(len - 40960, len) + s;
    else
        o.value += s;
    o.scrollTop = o.scrollHeight;
}

function __console_print(ptr)
{
    dolog(get_string(ptr));
}

let filestore = {}
let filestore_list = []
function __filestore_fetch(pathptr)
{
    const path = get_string(pathptr);
    filestore_list.push(path);
}

function __open_get_size(pathptr)
{
    const path = get_string(pathptr);
    if (path in filestore) {
        return filestore[path].length;
    }
    return -1;
}

function __open_get_content(pathptr, bufptr)
{
    const path = get_string(pathptr);
    if (path in filestore) {
        let i;
        const src = filestore[path];
        for (i = 0; i < src.length; i++)
            mem8[bufptr + i] = src[i];
        filestore[path] = null;
        return;
    }
    throw new Error('__open_get_content ' + path);
}

function drawfb(fbptr)
{
    const screen = document.getElementById('screen');
    const ctx = screen.getContext('2d');

    screen.width = 720;
    screen.height = 480;

    const data = ctx.createImageData(screen.width, screen.height);

    let i;
    const len = screen.width * screen.height;
    for (i = 0; i < len; i++) {
        data.data[4 * i + 0] = mem8[fbptr + 4 * i + 2];
        data.data[4 * i + 1] = mem8[fbptr + 4 * i + 1];
        data.data[4 * i + 2] = mem8[fbptr + 4 * i + 0];
        data.data[4 * i + 3] = 255;
    }
    ctx.putImageData(data, 0, 0);
}

// charmap, codemap taken from copy/v86
var charmap = new Uint16Array([
    0, 0, 0, 0,  0, 0, 0, 0,
    // 0x08: backspace, tab, enter
    0x0E, 0x0F, 0, 0,  0, 0x1C, 0, 0,

    // 0x10: shift, ctrl, alt, pause, caps lock
    0x2A, 0x1D, 0x38, 0,  0x3A, 0, 0, 0,

    // 0x18: escape
    0, 0, 0, 0x01,  0, 0, 0, 0,

    // 0x20: spacebar, page down/up, end, home, arrow keys, ins, del
    0x39, 0xE049, 0xE051, 0xE04F,  0xE047, 0xE04B, 0xE048, 0xE04D,
    0x50, 0, 0, 0,  0, 0x52, 0x53, 0,

    // 0x30: numbers
    0x0B, 0x02, 0x03, 0x04,  0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A,

    // 0x3B: ;= (firefox only)
    0, 0x27, 0, 0x0D, 0, 0,

    // 0x40
    0,

    // 0x41: letters
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,

    // 0x5B: Left Win, Right Win, Menu
    0xE05B, 0xE05C, 0xE05D, 0, 0,

    // 0x60: keypad
    0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47,
    0x48, 0x49, 0, 0, 0, 0, 0, 0,

    // 0x70: F1 to F12
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58,

    0, 0, 0, 0,

    // 0x80
    0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0,

    // 0x90: Numlock
    0x45, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,     0, 0, 0, 0,

    // 0xA0: - (firefox only)
    0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0x0C, 0, 0,

    // 0xB0
    0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0x27, 0x0D,  0x33, 0x0C, 0x34, 0x35,

    // 0xC0
    // `
    0x29, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,     0, 0, 0, 0,

    // 0xD0
    // [']\
    0, 0, 0, 0,     0, 0, 0, 0,
    0, 0, 0, 0x1A,  0x2B, 0x1B, 0x28, 0,

    // 0xE0
    // Apple key on Gecko, Right alt
    0xE05B, 0xE038, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,            0, 0, 0, 0,
]);

// From:
// https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/code#Code_values_on_Linux_%28X11%29_%28When_scancode_is_available%29
// http://stanislavs.org/helppc/make_codes.html
// http://www.computer-engineering.org/ps2keyboard/scancodes1.html
//
// Mapping from event.code to scancode
var codemap = {
    "Escape": 0x0001,
    "Digit1": 0x0002,
    "Digit2": 0x0003,
    "Digit3": 0x0004,
    "Digit4": 0x0005,
    "Digit5": 0x0006,
    "Digit6": 0x0007,
    "Digit7": 0x0008,
    "Digit8": 0x0009,
    "Digit9": 0x000a,
    "Digit0": 0x000b,
    "Minus": 0x000c,
    "Equal": 0x000d,
    "Backspace": 0x000e,
    "Tab": 0x000f,
    "KeyQ": 0x0010,
    "KeyW": 0x0011,
    "KeyE": 0x0012,
    "KeyR": 0x0013,
    "KeyT": 0x0014,
    "KeyY": 0x0015,
    "KeyU": 0x0016,
    "KeyI": 0x0017,
    "KeyO": 0x0018,
    "KeyP": 0x0019,
    "BracketLeft": 0x001a,
    "BracketRight": 0x001b,
    "Enter": 0x001c,
    "ControlLeft": 0x001d,
    "KeyA": 0x001e,
    "KeyS": 0x001f,
    "KeyD": 0x0020,
    "KeyF": 0x0021,
    "KeyG": 0x0022,
    "KeyH": 0x0023,
    "KeyJ": 0x0024,
    "KeyK": 0x0025,
    "KeyL": 0x0026,
    "Semicolon": 0x0027,
    "Quote": 0x0028,
    "Backquote": 0x0029,
    "ShiftLeft": 0x002a,
    "Backslash": 0x002b,
    "KeyZ": 0x002c,
    "KeyX": 0x002d,
    "KeyC": 0x002e,
    "KeyV": 0x002f,
    "KeyB": 0x0030,
    "KeyN": 0x0031,
    "KeyM": 0x0032,
    "Comma": 0x0033,
    "Period": 0x0034,
    "Slash": 0x0035,
    "IntlRo": 0x0035,
    "ShiftRight": 0x0036,
    "NumpadMultiply": 0x0037,
    "AltLeft": 0x0038,
    "Space": 0x0039,
    "CapsLock": 0x003a,
    "F1": 0x003b,
    "F2": 0x003c,
    "F3": 0x003d,
    "F4": 0x003e,
    "F5": 0x003f,
    "F6": 0x0040,
    "F7": 0x0041,
    "F8": 0x0042,
    "F9": 0x0043,
    "F10": 0x0044,
    "NumLock": 0x0045,
    "ScrollLock": 0x0046,
    "Numpad7": 0x0047,
    "Numpad8": 0x0048,
    "Numpad9": 0x0049,
    "NumpadSubtract": 0x004a,
    "Numpad4": 0x004b,
    "Numpad5": 0x004c,
    "Numpad6": 0x004d,
    "NumpadAdd": 0x004e,
    "Numpad1": 0x004f,
    "Numpad2": 0x0050,
    "Numpad3": 0x0051,
    "Numpad0": 0x0052,
    "NumpadDecimal": 0x0053,
    "IntlBackslash": 0x0056,
    "F11": 0x0057,
    "F12": 0x0058,

    "NumpadEnter": 0xe01c,
    "ControlRight": 0xe01d,
    "NumpadDivide": 0xe035,
    //"PrintScreen": 0x0063,
    "AltRight": 0xe038,
    "Home": 0xe047,
    "ArrowUp": 0xe048,
    "PageUp": 0xe049,
    "ArrowLeft": 0xe04b,
    "ArrowRight": 0xe04d,
    "End": 0xe04f,
    "ArrowDown": 0xe050,
    "PageDown": 0xe051,
    "Insert": 0xe052,
    "Delete": 0xe053,

    "OSLeft": 0xe05b,
    "OSRight": 0xe05c,
    "ContextMenu": 0xe05d,
};

function register_kbdmouse(h, exports)
{
    const screen = document.getElementById('screen');
    function mousehandler(event) {
        const x = event.movementX;
        const y = event.movementY;
        screen.tabIndex = 1;
        exports.wasm_send_mouse(h, x, y, 0, event.buttons);
    }

    screen.addEventListener('mousemove', mousehandler);
    screen.addEventListener('mousedown', mousehandler);
    screen.addEventListener('mouseup', mousehandler);

    function kbdhandler(ev, keypress) {
        const code = ev.code;
        if (code in codemap) {
            exports.wasm_send_kbd(h, keypress, codemap[code]);
        } else {
            const code = ev.keyCode;
            if (code < 256) {
                if (code in charmap)
                    exports.wasm_send_kbd(h, keypress, charmap[code]);
            }
        }
    }

    screen.addEventListener('keydown', (event) => kbdhandler(event, 1));
    screen.addEventListener('keyup', (event) => kbdhandler(event, 0));
}

const imports = {
    env: {
        __abort,
        exit,
        __get_mticks,
        __console_print,
        __filestore_fetch,
        __open_get_size,
        __open_get_content,
        sin: Math.sin,
        cos: Math.cos,
        pow: Math.pow,
        log10: Math.log10,
    }
};

const fetchopt = { cache: 'no-store' };

function loads(files, i, cont) {
    if (i == files.length)
        cont();
    else {
        dolog('fetch ' + files[i] + ' ...\n');
        fetch(files[i], fetchopt)
            .then(response => response.arrayBuffer())
            .then(bytes => {
                filestore[files[i]] = new Uint8Array(bytes);
                loads(files, i + 1, cont);
            });
    }
}

function start() {
    document.getElementById('startkey').disabled = true;
    fetch('tiny386.wasm', fetchopt)
        .then(response => response.arrayBuffer())
        .then(bytes => WebAssembly.compile(bytes))
        .then(module => new WebAssembly.Instance(module, imports))
        .then(instance => {
            instance.exports.memory.grow(1024 * 10); // 64K * 10K
            mem8 = new Uint8Array(instance.exports.memory.buffer);
            loads(["config.ini"], 0, () => {
                const h1 = instance.exports.wasm_prepare();
                loads(filestore_list, 0, () => {
                    const h2 = instance.exports.wasm_init(h1);
                    const fbptr = instance.exports.wasm_getfb(h2);
                    if (h2 != 0) {
                        register_kbdmouse(h2, instance.exports);

                        // web audio
                        const audctx = new window.AudioContext;
                        let playTime = audctx.currentTime;
                        const audlen = instance.exports.wasm_getaudiolen(h2);
                        const mf64 = new Float64Array(instance.exports.memory.buffer);
                        function setup_audio() {
                            const audbuf = audctx.createBuffer(1, audlen, 44100);
                            const audptr = instance.exports.wasm_getaudio(h2) / 8;

                            const buf = audbuf.getChannelData(0);
                            for (let i = 0; i < audlen; i++) {
                                buf[i] = mf64[audptr + i];
                            }
                            const bsn = audctx.createBufferSource();
                            bsn.buffer = audbuf;
                            bsn.connect(audctx.destination);
                            //bsn.onended = setup_audio;
                            bsn.start(audctx.currentTime);
                            playTime += audlen / 44100;
                        }
                        setup_audio();

                        // main loop
                        setInterval(() => {
                            instance.exports.wasm_loop(h2);
                        }, 1);

                        // redraw loop
                        setInterval(() => {
                            drawfb(fbptr);
                        }, 20);

                        // audio loop
                        setInterval(() => {
                            setup_audio();
                        }, audlen / 44100);
                    }
                });
            });
        });
}
