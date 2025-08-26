#ifndef SB16_H
#define SB16_H

#include <stdint.h>

typedef struct SB16State SB16State;
uint32_t sb16_dsp_read(void *opaque, uint32_t nport);
void sb16_dsp_write(void *opaque, uint32_t nport, uint32_t val);
uint32_t sb16_mixer_read(void *opaque, uint32_t nport);
void sb16_mixer_write_indexb(void *opaque, uint32_t nport, uint32_t val);
void sb16_mixer_write_datab(void *opaque, uint32_t nport, uint32_t val);
void sb16_audio_callback (void *opaque, uint8_t *stream, int free);

SB16State *sb16_new(
    int port, // 0x220
    int irq, // 5
    void *isa_hdma,
    void *isa_dma,
    void *pic,
    void (*set_irq)(void *pic, int irq, int level));

#endif /* SB16_H */
