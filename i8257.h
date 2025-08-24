#ifndef HW_I8257_H
#define HW_I8257_H
#include <stdbool.h>
#include <stdint.h>
typedef int (*IsaDmaTransferHandler)(void *opaque, int nchan, int dma_pos, int dma_len);

typedef struct I8257Regs {
    int now[2];
    uint16_t base[2];
    uint8_t mode;
    uint8_t page;
    uint8_t pageh;
    uint8_t dack;
    uint8_t eop;
    IsaDmaTransferHandler transfer_handler;
    void *opaque;
} I8257Regs;

typedef struct I8257State {
    int32_t base;
    int32_t page_base;
    int32_t pageh_base;
    int32_t dshift;

    uint8_t status;
    uint8_t command;
    uint8_t mask;
    uint8_t flip_flop;
    I8257Regs regs[4];
    char *phys_mem;
    long phys_mem_size;
//    MemoryRegion channel_io;
//    MemoryRegion cont_io;

//    QEMUBH *dma_bh;
    bool dma_bh_scheduled;
    int running;
//    PortioList portio_page;
//    PortioList portio_pageh;
} I8257State;

typedef uint32_t hwaddr;
typedef void IsaDma;

void i8257_dma_run(void *opaque);

uint32_t i8257_read_page(void *opaque, uint32_t nport);
uint32_t i8257_read_pageh(void *opaque, uint32_t nport);
void i8257_write_page(void *opaque, uint32_t nport, uint32_t data);
void i8257_write_pageh(void *opaque, uint32_t nport, uint32_t data);

uint64_t i8257_read_chan(void *opaque, hwaddr nport, unsigned size);
void i8257_write_chan(void *opaque, hwaddr nport, uint64_t data,
                      unsigned int size);

uint64_t i8257_read_cont(void *opaque, hwaddr nport, unsigned size);
void i8257_write_cont(void *opaque, hwaddr nport, uint64_t data,
                      unsigned int size);

void i8257_dma_register_channel(IsaDma *obj, int nchan,
                                IsaDmaTransferHandler transfer_handler,
                                void *opaque);
void i8257_dma_hold_DREQ(IsaDma *obj, int nchan);
void i8257_dma_release_DREQ(IsaDma *obj, int nchan);
int i8257_dma_read_memory(IsaDma *obj, int nchan, void *buf, int pos,
                          int len);
int i8257_dma_write_memory(IsaDma *obj, int nchan, void *buf, int pos,
                           int len);

I8257State *i8257_new(
    char *phys_mem, long phys_mem_size,
    int base, int page_base, int pageh_base, int dshift);
#endif
