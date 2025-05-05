LD=ld -m elf_i386
CC=gcc -m32
CFLAGS= -Os -Wall -fno-builtin -fno-stack-protector #-march=i386

all: linuxstart.bin

linuxstart.out: linuxstart_head.o linuxstart.o libc.o
	$(LD) -o $@ -N -Ttext 0x00010000 $^

linuxstart.bin: linuxstart.out
	objcopy -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS)  -c -o $@ $<

%.o: %.S
	$(CC) -m32 -D__ASSEMBLY__ -c -o $@ $<

clean:
	rm -f linuxstart.bin linuxstart.out *.o *~

