#!/usr/bin/env python3
"""Exact binary-rational PC24 oracle; no host float arithmetic for expected results.
Usage: python3 tests/check-fpu.py /tmp/fpu-rounding
Normal binary64 inputs/results only: does not validate float80 range or exceptions.
"""
from fractions import Fraction as F
from math import isqrt
import random
import struct
import subprocess
import sys


def pow2(e):
    return F(2**e) if e >= 0 else F(1, 2**-e)


def exponent(x):
    e = x.numerator.bit_length() - x.denominator.bit_length()
    return e - (x < pow2(e))


def rounded(x, rc, sqrt=False):
    if not x:
        return 0.0
    negative = x < 0
    x = abs(x)
    e = exponent(x) // 2 if sqrt else exponent(x)
    unit = pow2(e - 23)
    scaled = x / (unit * unit if sqrt else unit)
    n, d = scaled.numerator, scaled.denominator
    if sqrt:
        q = isqrt(n // d)
        exact = q * q * d == n
        cmp = 4 * n - d * (2 * q + 1)**2
    else:
        q, remainder = divmod(n, d)
        exact = remainder == 0
        cmp = 2 * remainder - d
    increment = ((cmp > 0 or (cmp == 0 and q % 2)) if rc == 0 else
                 (not exact and (negative if rc == 1 else not negative)) if rc != 3 else False)
    answer = (q + increment) * unit
    return float(-answer if negative else answer)  # PC24 is exactly representable here


def raw(x):
    return struct.unpack('>Q', struct.pack('>d', x))[0]


rng = random.Random(386)
pairs = [(1.0, 2.0**-100), (1.0 + 2.0**-24, 2.0**-54),
         (1.0 + 2.0**-24, -2.0**-54), (1.0, -2.0**-100),
         (1.0 + 2.0**-23, 2.0**-24), (1.0, 3.0)]
for _ in range(1200):
    a = float(F(rng.randrange(2**52, 2**53), 2**52) * pow2(rng.randint(-400, 400)))
    b = float(F(rng.randrange(2**52, 2**53), 2**52) * pow2(rng.randint(-400, 400)))
    pairs.append((a, b))
# Concentrate on 24-bit boundaries and host-double ties in every exponent range.
for e in (-400, -100, 0, 100, 400):
    for last in (0, 1, 2, 3, 2**23 - 1):
        for delta in (-100, -54, -53, -24, -23):
            pairs.append((float((1 + F(last, 2**23)) * pow2(e)), float(pow2(e + delta))))

cases = []
for a, b in pairs:
    for sa, sb in ((1, 1), (-1, 1), (1, -1), (-1, -1)):
        a1, b1 = a * sa, b * sb
        aa, bb = F(a1), F(b1)
        for op, result in ((0, aa + bb), (1, aa * bb), (4, aa - bb),
                           (5, bb - aa), (6, aa / bb), (7, bb / aa)):
            if not result:  # signed cancellation zero is a separate, pre-existing limitation
                continue
            for rc in range(4):
                cases.append((op, rc, a1, b1, raw(rounded(result, rc))))
    for rc in range(4):
        cases.append((8, rc, a, 0.0, raw(rounded(F(a), rc, sqrt=True))))

payload = ''.join(f'{op} {rc} {raw(a):x} {raw(b):x}\n' for op, rc, a, b, _ in cases)
process = subprocess.run([sys.argv[1], '--stream'], input=payload, text=True,
                         stdout=subprocess.PIPE, check=True)
answers = process.stdout.splitlines()
assert len(answers) == len(cases)
for case, actual in zip(cases, answers):
    op, rc, a, b, expected = case
    assert int(actual, 16) == expected, (op, rc, a.hex(), b.hex(), hex(expected), actual)
print(f'PC24 exact rational oracle: {len(cases)} results passed (all arithmetic forms, sqrt, four RC modes)')
