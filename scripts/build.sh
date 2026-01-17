#!/bin/bash
build_seabios() {
    git clone https://github.com/coreboot/seabios.git &&
	cd seabios &&
	patch -p1 < ../../seabios/patch &&
	cp ../../seabios/config ./.config &&
	make oldconfig &&
	make &&
	cp out/bios.bin out/vgabios.bin ../../out/ &&
	cd ..
}

build_sdl() {
    git clone https://github.com/libsdl-org/SDL-1.2.git &&
	cd SDL-1.2 &&
	patch -p1 < ../../scripts/sdl.patch &&
	mkdir -p build && cd build &&
	CFLAGS="-Os -ffunction-sections -fdata-sections" ../configure --disable-shared --disable-joystick --disable-cdrom --enable-alsa --disable-oss --disable-esd --disable-sndio --disable-pulseaudio --prefix="$PWD" &&
	make &&
	make install &&
	cd .. &&
	mkdir -p build-mingw32 && cd build-mingw32 &&
	CFLAGS="-Os -ffunction-sections -fdata-sections" ../configure --disable-shared --host=i686-w64-mingw32 --disable-stdio-redirect --prefix="$PWD" &&
	make &&
	make install &&
	cd .. &&
	cd ..
}

build_slirp() {
    cp -r ../scripts/slirp . &&
	cd slirp &&
	git clone -b v4.9.1 --depth=1 https://gitlab.freedesktop.org/slirp/libslirp.git slirp &&
	cd slirp && patch -p1 < ../patch && cd .. &&
	make && make install DESTDIR=build && make clean &&
	make win32 && make install DESTDIR=build-mingw32 && make clean &&
	cd ..
}

build_thirdparty() {
    mkdir -p out &&
    mkdir -p build && cd build &&
	build_seabios &&
	build_slirp &&
    cd .. &&
    make prepare
}

build_tiny386() {
    mkdir -p out &&
	cd linuxstart && make && cd .. && cp linuxstart/linuxstart.bin out/ &&
	make clean &&
	make \
	     SLIRP_INC="-I$PWD/build/slirp/build" \
	     SLIRP_LIB="-L$PWD/build/slirp/build -lslirp" all &&
	strip -s tiny386 tiny386_nosdl tiny386_kvm wifikbd initnet &&
	cp tiny386 tiny386_nosdl tiny386_kvm wifikbd initnet out &&
	mkdir -p out/win32 &&
	make clean &&
	make \
	     SLIRP_INC="-I$PWD/build/slirp/build-mingw32 -DLIBSLIRP_STATIC" \
	     SLIRP_LIB="-L$PWD/build/slirp/build-mingw32 -lslirp" win32 &&
	strip -s tiny386.exe wifikbd.exe &&
	cp tiny386.exe wifikbd.exe out/win32 &&
	make clean &&
	rm tiny386.exe wifikbd.exe &&
	cd wasm && make && cd .. &&
	mkdir -p out/wasm &&
	cp wasm/html/tiny386.wasm out/wasm &&
	cp wasm/html/index.html out/wasm &&
	cp wasm/html/main.js out/wasm
}

patch_idf() {
    PDIR="$PWD"
    cd "$IDF_PATH" &&
    patch -p1 < "$PDIR/esp/esp-idf.patch" &&
    cd "$PDIR"
}

build_esp() {
    mkdir -p out/esp &&
	cd esp && idf.py build &&
	cd build &&
	esptool.py --chip esp32s3 merge_bin -o flash_image_JC3248W535.bin '@flash_args' &&
	cd .. &&
	cp build/flash_image*.bin ../out/esp &&
	cp tiny386.ini ../out/esp &&
	cd ..
}

bundle() {
    cp README.md LICENSE out
    tar cJf tiny386.tar.xz out --transform 's/^out/tiny386/'
}

if [ "$1" == "thirdparty" ]; then
    build_thirdparty
elif [ "$1" == "tiny386" ]; then
    build_tiny386
elif [ "$1" == "patch_idf" ]; then
    patch_idf
elif [ "$1" == "esp" ]; then
    build_esp
elif [ "$1" == "bundle" ]; then
    bundle
fi
