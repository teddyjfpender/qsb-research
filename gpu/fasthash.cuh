/* fasthash.cuh -- register-resident, fully inlined SHA-256 and RIPEMD-160 compressions.
 * Written for pool2.cu (not derived from GPUHash.h). Message words are passed by value in a
 * fully unrolled context so constant words (padding, zeros) fold at compile time.
 */
#pragma once
#include <stdint.h>

__device__ __forceinline__ uint32_t rotr32(uint32_t x, int n) { return __funnelshift_r(x, x, n); }
__device__ __forceinline__ uint32_t rotl32(uint32_t x, int n) { return __funnelshift_l(x, x, n); }

/* ------------------------------------------------------------------ SHA-256 */
#define SHA_K0  0x428a2f98u
__device__ __forceinline__ void sha256_fast(uint32_t st[8], const uint32_t win[16]) {
    const uint32_t Kc[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[16];
#pragma unroll
    for (int i = 0; i < 16; i++) w[i] = win[i];
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) wi = w[i];
        else {
            const uint32_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
            const uint32_t s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3);
            const uint32_t s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10);
            wi = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
            w[i & 15] = wi;
        }
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = g ^ (e & (f ^ g));
        const uint32_t t1 = h + S1 + ch + Kc[i] + wi;
        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t mj = (a & b) | (c & (a | b));
        const uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

__device__ __forceinline__ void sha256_init(uint32_t s[8]) {
    s[0] = 0x6a09e667; s[1] = 0xbb67ae85; s[2] = 0x3c6ef372; s[3] = 0xa54ff53a;
    s[4] = 0x510e527f; s[5] = 0x9b05688c; s[6] = 0x1f83d9ab; s[7] = 0x5be0cd19;
}

/* ------------------------------------------------------------------ RIPEMD-160 */
__device__ __forceinline__ uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z) {
    return j < 16 ? (x ^ y ^ z) : j < 32 ? (z ^ (x & (y ^ z))) : j < 48 ? ((x | ~y) ^ z)
         : j < 64 ? (y ^ (z & (x ^ y))) : (x ^ (y | ~z));
}

__device__ __forceinline__ void ripemd160_fast(uint32_t h[5], const uint32_t X[16]) {
    const int RL[80] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
    const int RR[80] = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
    const int SL[80] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
    const int SR[80] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
    const uint32_t KL[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
    const uint32_t KR[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
#pragma unroll
    for (int j = 0; j < 80; j++) {
        uint32_t t = rotl32(al + rmd_f(j, bl, cl, dl) + X[RL[j]] + KL[j >> 4], SL[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = t;
        t = rotl32(ar + rmd_f(79 - j, br, cr, dr) + X[RR[j]] + KR[j >> 4], SR[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = t;
    }
    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er; h[2] = h[3] + el + ar; h[3] = h[4] + al + br; h[4] = h[0] + bl + cr; h[0] = t;
}

__device__ __forceinline__ void ripemd160_init(uint32_t s[5]) {
    s[0] = 0x67452301; s[1] = 0xEFCDAB89; s[2] = 0x98BADCFE; s[3] = 0x10325476; s[4] = 0xC3D2E1F0;
}
