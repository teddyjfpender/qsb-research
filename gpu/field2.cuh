/* field2.cuh -- carry-safe secp256k1 field arithmetic (64-bit limbs, unsigned __int128). */
#pragma once
#include <stdint.h>
/* ================================================================== field: p = 2^256 - PC */
typedef unsigned __int128 u128;
#define PC 0x1000003D1ULL

__device__ __forceinline__ void fcopy(uint64_t r[4], const uint64_t a[4]) { r[0] = a[0]; r[1] = a[1]; r[2] = a[2]; r[3] = a[3]; }

/* r = a*b mod p, loosely reduced (< 2^256). Any inputs < 2^256. */
__device__ __forceinline__ void fmul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[8];
    u128 acc = 0;
#pragma unroll
    for (int j = 0; j < 4; j++) { acc += (u128)a[0] * b[j]; t[j] = (uint64_t)acc; acc >>= 64; }
    t[4] = (uint64_t)acc;
#pragma unroll
    for (int i = 1; i < 4; i++) {
        acc = 0;
#pragma unroll
        for (int j = 0; j < 4; j++) { acc += (u128)a[i] * b[j] + t[i + j]; t[i + j] = (uint64_t)acc; acc >>= 64; }
        t[i + 4] = (uint64_t)acc;
    }
    acc = 0;
    uint64_t q[4];
#pragma unroll
    for (int i = 0; i < 4; i++) { acc += (u128)t[i + 4] * PC + t[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    acc = (u128)(uint64_t)acc * PC + q[0]; q[0] = (uint64_t)acc; acc >>= 64;
#pragma unroll
    for (int i = 1; i < 4; i++) { acc += q[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    if ((uint64_t)acc) {                                           /* wrapped past 2^256: q is tiny, add PC */
        acc = (u128)q[0] + PC; q[0] = (uint64_t)acc; acc >>= 64;
#pragma unroll
        for (int i = 1; i < 4; i++) { acc += q[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    }
    fcopy(r, q);
}

/* r = a^2 mod p (10 products instead of 16) */
__device__ __forceinline__ void fsqr(uint64_t r[4], const uint64_t a[4]) {
    uint64_t t[8];
    u128 acc;
    /* cross products a_i a_j, i<j, into t[1..6] */
    acc = (u128)a[0] * a[1];               t[1] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[0] * a[2];              t[2] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[0] * a[3];              t[3] = (uint64_t)acc; acc >>= 64;
    t[4] = (uint64_t)acc;
    acc = (u128)a[1] * a[2] + t[3];        t[3] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[1] * a[3] + t[4];       t[4] = (uint64_t)acc; acc >>= 64;
    t[5] = (uint64_t)acc;
    acc = (u128)a[2] * a[3] + t[5];        t[5] = (uint64_t)acc; acc >>= 64;
    t[6] = (uint64_t)acc;
    /* double */
    t[7] = t[6] >> 63;
    t[6] = (t[6] << 1) | (t[5] >> 63); t[5] = (t[5] << 1) | (t[4] >> 63);
    t[4] = (t[4] << 1) | (t[3] >> 63); t[3] = (t[3] << 1) | (t[2] >> 63);
    t[2] = (t[2] << 1) | (t[1] >> 63); t[1] = t[1] << 1;
    /* add squares */
    acc = (u128)a[0] * a[0];               t[0] = (uint64_t)acc; acc >>= 64;
    acc += t[1];                           t[1] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[1] * a[1] + t[2];       t[2] = (uint64_t)acc; acc >>= 64;
    acc += t[3];                           t[3] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[2] * a[2] + t[4];       t[4] = (uint64_t)acc; acc >>= 64;
    acc += t[5];                           t[5] = (uint64_t)acc; acc >>= 64;
    acc += (u128)a[3] * a[3] + t[6];       t[6] = (uint64_t)acc; acc >>= 64;
    acc += t[7];                           t[7] = (uint64_t)acc;
    acc = 0;
    uint64_t q[4];
#pragma unroll
    for (int i = 0; i < 4; i++) { acc += (u128)t[i + 4] * PC + t[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    acc = (u128)(uint64_t)acc * PC + q[0]; q[0] = (uint64_t)acc; acc >>= 64;
#pragma unroll
    for (int i = 1; i < 4; i++) { acc += q[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    if ((uint64_t)acc) {
        acc = (u128)q[0] + PC; q[0] = (uint64_t)acc; acc >>= 64;
#pragma unroll
        for (int i = 1; i < 4; i++) { acc += q[i]; q[i] = (uint64_t)acc; acc >>= 64; }
    }
    fcopy(r, q);
}

__device__ __forceinline__ uint64_t addc64(uint64_t a, uint64_t b, uint64_t &c) {
    uint64_t s = a + c; uint64_t c1 = s < c; s += b; c = c1 | (s < b); return s;
}

__device__ __forceinline__ void fadd(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t q[4], c = 0;
#pragma unroll
    for (int i = 0; i < 4; i++) q[i] = addc64(a[i], b[i], c);
#pragma unroll
    for (int rep = 0; rep < 2; rep++) {                  /* 2^256 == PC (mod p); at most twice */
        if (c) { c = 0; q[0] = addc64(q[0], PC, c); q[1] = addc64(q[1], 0, c); q[2] = addc64(q[2], 0, c); q[3] = addc64(q[3], 0, c); }
    }
    fcopy(r, q);
}

__device__ __forceinline__ void fsub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t q[4]; uint64_t borrow = 0;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        uint64_t d = a[i] - b[i]; uint64_t b1 = a[i] < b[i];
        uint64_t d2 = d - borrow; uint64_t b2 = d < borrow;
        q[i] = d2; borrow = b1 | b2;
    }
#pragma unroll
    for (int rep = 0; rep < 2; rep++) {                  /* wrapped below 0: subtract PC (== add p) */
        if (!borrow) break;
        uint64_t bb = PC; borrow = 0;
#pragma unroll
        for (int i = 0; i < 4; i++) {
            uint64_t d = q[i] - bb; uint64_t b1 = q[i] < bb;
            uint64_t d2 = d - borrow; uint64_t b2 = d < borrow;
            q[i] = d2; borrow = b1 | b2; bb = 0;
        }
    }
    fcopy(r, q);
}

/* canonical representative in [0, p) */
__device__ __forceinline__ void fcanon(uint64_t r[4]) {
    u128 acc = (u128)r[0] + PC; uint64_t s[4]; s[0] = (uint64_t)acc; acc >>= 64;
#pragma unroll
    for (int i = 1; i < 4; i++) { acc += r[i]; s[i] = (uint64_t)acc; acc >>= 64; }
    if ((uint64_t)acc) fcopy(r, s);
}

__device__ __forceinline__ void finv(uint64_t r[4], const uint64_t a[4]) {
    uint64_t t[5]; fcopy(t, a); fcanon(t); t[4] = 0; _ModInv(t); fcopy(r, t); fcanon(r);
}

