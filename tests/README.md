Run from the repository root (C99 compiler/libm and Python 3):

```sh
cc -O2 -DI386_ENABLE_FPU tests/fpu-rounding.c i386.c -lm -o /tmp/fpu-rounding
/tmp/fpu-rounding
python3 tests/check-fpu.py /tmp/fpu-rounding
```

The C checks reproduce the directed FADD (1 + 2^-100) and nearest halfway
((1 + 2^-24) + 2^-54) failures, exact arithmetic, FSQRT instruction dispatch,
and NaN propagation for both operand orders in every binary arithmetic group.
The directed FADD assertion fails on the original PR head.

The independent Python oracle uses exact rational arithmetic (integer square
root/comparisons for FSQRT), then rounds once to PC24. It covers 133,100 results
with a fixed random seed, all four rounding modes, both signs, FADD/FMUL/FSUB/
FSUBR/FDIV/FDIVR/FSQRT, exponent variation, and boundary/tie cases.
NaN precedence follows the x87/8086 specialization of Berkeley SoftFloat:
https://github.com/ucb-bar/berkeley-softfloat-3/blob/master/source/8086/s_propagateNaNF64UI.c

Validation was on ARM64 macOS with Clang and GCC. There was no native x87,
QEMU differential run, or full guest boot in this follow-up. The oracle
checks normal binary64-range results, not complete x87 emulation. Existing
limits remain: binary64 register precision/exponent range, subnormal and
underflow/overflow behavior, signed cancellation zero in directed modes,
and missing x87 exceptions/tag semantics. USE_FLOAT80 retains its existing
path. Host round-to-nearest and no fast-math/reassociation are required.
