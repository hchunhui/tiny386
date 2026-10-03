NDK = /tmp/android-ndk-r30
BUILD_TOOLS = /usr/bin

APPNAME = tiny386
RAWDRAWANDROID = rawdrawandroid
CFLAGS = -I.. -ffunction-sections -O3 -fvisibility=hidden
CFLAGS += -DI386_ENABLE_FPU
CFLAGS += -DI386_ENABLE_MMX -DI386_ENABLE_SSE -DI386_ENABLE_SSE2 -DI386_ENABLE_SSE3
CFLAGS += -DI386_ENABLE_SSSE3
CFLAGS += -DUSE_FMOPL
LDFLAGS = -Wl,--gc-sections -s
PACKAGENAME = org.yourorg.$(APPNAME)
SRC = \
../ini.c \
../i386.c \
../fpu.c \
../i8259.c \
../i8254.c \
../ide.c \
../vga.c \
../vgafont.c \
../i8042.c \
../misc.c \
../fmopl.c \
../adlib.c \
../ne2000.c \
../i8257.c \
../sb16.c \
../pcspk.c \
../pci.c \
../pc.c \
../term.c \
../osd/microui.c \
../osd/osd.c \
vkbd.c \
../rawdraw/main.c

SLIRP_DIR = ../build/slirp/build-android-aarch64
CFLAGS += -DUSE_SLIRP
CFLAGS += -I$(SLIRP_DIR)
LDFLAGS += -L$(SLIRP_DIR) -lslirp

ANDROIDVERSION = 30
ANDROIDTARGET = 30

TARGETS = makecapk/lib/arm64-v8a/lib$(APPNAME).so
#TARGETS += makecapk/lib/armeabi-v7a/lib$(APPNAME).so
#TARGETS += makecapk/lib/x86/lib$(APPNAME).so
#TARGETS += makecapk/lib/x86_64/lib$(APPNAME).so

include rawdrawandroid/Makefile
