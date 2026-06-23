LD=ld
CC=gcc
CFLAGS= -Os -Wall -fno-builtin -fno-stack-protector

all: linuxstart.bin

linuxstart32.out: linuxstart_head32.o linuxstart32.o libc32.o
	$(LD) -m elf_i386 -o $@ -N -Ttext 0x00010000 $^

linuxstart64.out: linuxstart_head64.o linuxstart64.o libc64.o
	$(LD) -m elf_x86_64 -o $@ -N -Ttext 0x0 $^

linuxstart64.bin: linuxstart64.out
	objcopy -O binary $< $@

linuxstart.bin: linuxstart32.out
	objcopy -O binary $< $@

linuxstart_head32.o: linuxstart64.bin

%32.o: %.c
	$(CC) -m32 $(CFLAGS)  -c -o $@ $<

%32.o: %.S
	$(CC) -m32 -D__ASSEMBLY__ -c -o $@ $<

%64.o: %.c
	$(CC) -m64 -fPIC $(CFLAGS)  -c -o $@ $<

%64.o: %.S
	$(CC) -m64 -fPIC -D__ASSEMBLY__ -c -o $@ $<

clean:
	rm -f linuxstart.bin linuxstart64.bin linuxstart32.out linuxstart64.out *.o *~

