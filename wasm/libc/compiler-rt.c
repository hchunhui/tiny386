// addapted from llvm/compiler-rt
#include <stdint.h>
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

typedef union
{
	int128_t all;
	struct
	{
		uint64_t low;
		int64_t high;
	}s;
} twords;

typedef union
{
	uint128_t all;
	struct
	{
		uint64_t low;
		uint64_t high;
	}s;
} utwords;

#define CHAR_BIT 8

//===-- multi3.c - Implement __multi3 -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __multi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

// Returns: a * b

static int128_t __mulddi3(uint64_t a, uint64_t b) {
	twords r;
	const int bits_in_dword_2 = (int)(sizeof(int64_t) * CHAR_BIT) / 2;
	const uint64_t lower_mask = (uint64_t)~0 >> bits_in_dword_2;
	r.s.low = (a & lower_mask) * (b & lower_mask);
	uint64_t t = r.s.low >> bits_in_dword_2;
	r.s.low &= lower_mask;
	t += (a >> bits_in_dword_2) * (b & lower_mask);
	r.s.low += (t & lower_mask) << bits_in_dword_2;
	r.s.high = t >> bits_in_dword_2;
	t = r.s.low >> bits_in_dword_2;
	r.s.low &= lower_mask;
	t += (b >> bits_in_dword_2) * (a & lower_mask);
	r.s.low += (t & lower_mask) << bits_in_dword_2;
	r.s.high += t >> bits_in_dword_2;
	r.s.high += (a >> bits_in_dword_2) * (b >> bits_in_dword_2);
	return r.all;
}

// Returns: a * b

int128_t __multi3(int128_t a, int128_t b) {
	twords x;
	x.all = a;
	twords y;
	y.all = b;
	twords r;
	r.all = __mulddi3(x.s.low, y.s.low);
	r.s.high += x.s.high * y.s.low + x.s.low * y.s.high;
	return r.all;
}

//===-- udivmodti4.c - Implement __udivmodti4 -----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __udivmodti4 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

// Returns the 128 bit division result by 64 bit. Result must fit in 64 bits.
// Remainder stored in r.
// Taken and adjusted from libdivide libdivide_128_div_64_to_64 division
// fallback. For a correctness proof see the reference for this algorithm
// in Knuth, Volume 2, section 4.3.1, Algorithm D.
static inline uint64_t udiv128by64to64default(uint64_t u1, uint64_t u0, uint64_t v,
					      uint64_t *r) {
	const unsigned n_udword_bits = sizeof(uint64_t) * CHAR_BIT;
	const uint64_t b = (1ULL << (n_udword_bits / 2)); // Number base (32 bits)
	uint64_t un1, un0;                                // Norm. dividend LSD's
	uint64_t vn1, vn0;                                // Norm. divisor digits
	uint64_t q1, q0;                                  // Quotient digits
	uint64_t un64, un21, un10;                        // Dividend digit pairs
	uint64_t rhat;                                    // A remainder
	int32_t s;                                       // Shift amount for normalization

	s = __builtin_clzll(v);
	if (s > 0) {
		// Normalize the divisor.
		v = v << s;
		un64 = (u1 << s) | (u0 >> (n_udword_bits - s));
		un10 = u0 << s; // Shift dividend left
	} else {
		// Avoid undefined behavior of (u0 >> 64).
		un64 = u1;
		un10 = u0;
	}

	// Break divisor up into two 32-bit digits.
	vn1 = v >> (n_udword_bits / 2);
	vn0 = v & 0xFFFFFFFF;

	// Break right half of dividend into two digits.
	un1 = un10 >> (n_udword_bits / 2);
	un0 = un10 & 0xFFFFFFFF;

	// Compute the first quotient digit, q1.
	q1 = un64 / vn1;
	rhat = un64 - q1 * vn1;

	// q1 has at most error 2. No more than 2 iterations.
	while (q1 >= b || q1 * vn0 > b * rhat + un1) {
		q1 = q1 - 1;
		rhat = rhat + vn1;
		if (rhat >= b)
			break;
	}

	un21 = un64 * b + un1 - q1 * v;

	// Compute the second quotient digit.
	q0 = un21 / vn1;
	rhat = un21 - q0 * vn1;

	// q0 has at most error 2. No more than 2 iterations.
	while (q0 >= b || q0 * vn0 > b * rhat + un0) {
		q0 = q0 - 1;
		rhat = rhat + vn1;
		if (rhat >= b)
			break;
	}

	*r = (un21 * b + un0 - q0 * v) >> s;
	return q1 * b + q0;
}

static inline uint64_t udiv128by64to64(uint64_t u1, uint64_t u0, uint64_t v,
				       uint64_t *r) {
	return udiv128by64to64default(u1, u0, v, r);
}

// Effects: if rem != 0, *rem = a % b
// Returns: a / b

uint128_t __udivmodti4(uint128_t a, uint128_t b, uint128_t *rem) {
	const unsigned n_utword_bits = sizeof(uint128_t) * CHAR_BIT;
	utwords dividend;
	dividend.all = a;
	utwords divisor;
	divisor.all = b;
	utwords quotient;
	utwords remainder;
	if (divisor.all > dividend.all) {
		if (rem)
			*rem = dividend.all;
		return 0;
	}
	// When the divisor fits in 64 bits, we can use an optimized path.
	if (divisor.s.high == 0) {
		remainder.s.high = 0;
		if (dividend.s.high < divisor.s.low) {
			// The result fits in 64 bits.
			quotient.s.low = udiv128by64to64(dividend.s.high, dividend.s.low,
							 divisor.s.low, &remainder.s.low);
			quotient.s.high = 0;
		} else {
			// First, divide with the high part to get the remainder in dividend.s.high.
			// After that dividend.s.high < divisor.s.low.
			quotient.s.high = dividend.s.high / divisor.s.low;
			dividend.s.high = dividend.s.high % divisor.s.low;
			quotient.s.low = udiv128by64to64(dividend.s.high, dividend.s.low,
							 divisor.s.low, &remainder.s.low);
		}
		if (rem)
			*rem = remainder.all;
		return quotient.all;
	}
	// 0 <= shift <= 63.
	int32_t shift =
		__builtin_clzll(divisor.s.high) - __builtin_clzll(dividend.s.high);
	divisor.all <<= shift;
	quotient.s.high = 0;
	quotient.s.low = 0;
	for (; shift >= 0; --shift) {
		quotient.s.low <<= 1;
		// Branch free version of.
		// if (dividend.all >= divisor.all)
		// {
		//    dividend.all -= divisor.all;
		//    carry = 1;
		// }
		const int128_t s =
			(int128_t)(divisor.all - dividend.all - 1) >> (n_utword_bits - 1);
		quotient.s.low |= s & 1;
		dividend.all -= divisor.all & s;
		divisor.all >>= 1;
	}
	if (rem)
		*rem = dividend.all;
	return quotient.all;
}

//===-- udivti3.c - Implement __udivti3 -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __udivti3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

// Returns: a / b

uint128_t __udivti3(uint128_t a, uint128_t b) {
	return __udivmodti4(a, b, 0);
}

//===-- divti3.c - Implement __divti3 -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __divti3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

// Returns: a / b

#define fixint_t int128_t
#define fixuint_t uint128_t
#define COMPUTE_UDIV(a, b) __udivmodti4((a), (b), (uint128_t *)0)

#define clz(a) __builtin_clzll(a)

// Adapted from Figure 3-40 of The PowerPC Compiler Writer's Guide
static __inline fixuint_t __udivXi3(fixuint_t n, fixuint_t d) {
	const unsigned N = sizeof(fixuint_t) * CHAR_BIT;
	// d == 0 cases are unspecified.
	unsigned sr = (d ? clz(d) : N) - (n ? clz(n) : N);
	// 0 <= sr <= N - 1 or sr is very large.
	if (sr > N - 1) // n < d
		return 0;
	if (sr == N - 1) // d == 1
		return n;
	++sr;
	// 1 <= sr <= N - 1. Shifts do not trigger UB.
	fixuint_t r = n >> sr;
	n <<= N - sr;
	fixuint_t carry = 0;
	for (; sr > 0; --sr) {
		r = (r << 1) | (n >> (N - 1));
		n = (n << 1) | carry;
		// Branch-less version of:
		// carry = 0;
		// if (r >= d) r -= d, carry = 1;
		const fixint_t s = (fixint_t)(d - r - 1) >> (N - 1);
		carry = s & 1;
		r -= d & s;
	}
	n = (n << 1) | carry;
	return n;
}

// Mostly identical to __udivXi3 but the return values are different.
static __inline fixuint_t __umodXi3(fixuint_t n, fixuint_t d) {
	const unsigned N = sizeof(fixuint_t) * CHAR_BIT;
	// d == 0 cases are unspecified.
	unsigned sr = (d ? clz(d) : N) - (n ? clz(n) : N);
	// 0 <= sr <= N - 1 or sr is very large.
	if (sr > N - 1) // n < d
		return n;
	if (sr == N - 1) // d == 1
		return 0;
	++sr;
	// 1 <= sr <= N - 1. Shifts do not trigger UB.
	fixuint_t r = n >> sr;
	n <<= N - sr;
	fixuint_t carry = 0;
	for (; sr > 0; --sr) {
		r = (r << 1) | (n >> (N - 1));
		n = (n << 1) | carry;
		// Branch-less version of:
		// carry = 0;
		// if (r >= d) r -= d, carry = 1;
		const fixint_t s = (fixint_t)(d - r - 1) >> (N - 1);
		carry = s & 1;
		r -= d & s;
	}
	return r;
}

static __inline fixint_t __divXi3(fixint_t a, fixint_t b) {
	const int N = (int)(sizeof(fixint_t) * CHAR_BIT) - 1;
	fixint_t s_a = a >> N;                            // s_a = a < 0 ? -1 : 0
	fixint_t s_b = b >> N;                            // s_b = b < 0 ? -1 : 0
	fixuint_t a_u = (fixuint_t)(a ^ s_a) + (-s_a);    // negate if s_a == -1
	fixuint_t b_u = (fixuint_t)(b ^ s_b) + (-s_b);    // negate if s_b == -1
	s_a ^= s_b;                                       // sign of quotient
	return (COMPUTE_UDIV(a_u, b_u) ^ s_a) + (-s_a);   // negate if s_a == -1
}

int128_t __divti3(int128_t a, int128_t b) { return __divXi3(a, b); }

//===-- ashlti3.c - Implement __ashlti3 -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __ashlti3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

// Returns: a << b

// Precondition:  0 <= b < bits_in_tword

int128_t __ashlti3(int128_t a, int b) {
	const int bits_in_dword = (int)(sizeof(int64_t) * CHAR_BIT);
	twords input;
	twords result;
	input.all = a;
	if (b & bits_in_dword) /* bits_in_dword <= b < bits_in_tword */ {
		result.s.low = 0;
		result.s.high = input.s.low << (b - bits_in_dword);
	} else /* 0 <= b < bits_in_dword */ {
		if (b == 0)
			return a;
		result.s.low = input.s.low << b;
		result.s.high =
			((uint64_t)input.s.high << b) | (input.s.low >> (bits_in_dword - b));
	}
	return result.all;
}
