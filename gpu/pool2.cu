/* pool2.cu -- tuned GPU kernel for the QSB nonce-signature pool (see README.md, "pool2").
 *
 * Changes vs pool.cu:
 *   1. All three consensus-valid key encodings are hashed for every point (compressed 1 block,
 *      uncompressed 2 blocks, hybrid 2 blocks). The security model already grants them to both
 *      parties; for the honest spender they are shots that cost hash blocks but no EC work.
 *   2. Carry-safe field arithmetic: 64-bit limbs with unsigned __int128 accumulation, so the
 *      compiler owns every carry chain (pool.cu's VanitySearch macros split chains across asm
 *      statements and miscompiled one instantiation). Only _ModInv is still VanitySearch's.
 *   3. Setup uses Jacobian mixed additions (8M+3S) instead of CudaBrainSecp's homogeneous add, and
 *      one batched inversion over the candidates' Z; the pool's x-differences are batched over up
 *      to 256 elements per thread, storing only prefix products (dx is recomputed).
 *
 * Hit record: seq, lt, j, (sign | enc << 1)   with enc 0 = 02/03, 1 = 04, 2 = 06/07.
 * Build: nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -o pool2 pool2.cu -lcrypto -lgomp
 * Run:   ./pool2 <pinning.bin> <K> <sha|rmd> <zeros|der> <N> <seconds> <extra_blocks> <hits_out> [enc 1|3]
 * GPLv3 (uses VanitySearch GPUMath.h/_ModInv and GPUHash.h SHA-256/RIPEMD-160 transforms).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>
#include "GPUMath.h"
#define MAX_LEN_WORD_PRIME 20
#define MAX_LEN_WORD_AFFIX 4
#define AFFIX_IS_SUFFIX true
#define SIZE_COMBO_MULTI 4
#define COUNT_COMBO_SYMBOLS 100
#define IDX_CUDA_THREAD ((blockIdx.x * blockDim.x) + threadIdx.x)
__device__ __constant__ int MULTI_EIGHT[65] = {0};
__device__ __constant__ uint8_t COMBO_SYMBOLS[100] = {0};
#include "GPUHash.h"
#include "fasthash.cuh"

extern "C" {
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
}

#define KMAX 512
#define MZMAX 32
#ifndef BMAX
#define BMAX 512
#endif
__constant__ uint32_t cMid[8];
__constant__ uint8_t cSuffix[128];
__constant__ int cSufLen, cSeqOff, cLtOff, cTotalLen, cZeros;
__constant__ uint32_t cXW[16];
__constant__ uint64_t cJX[KMAX][4], cJY[KMAX][4];
#ifdef ROUND_MODE
/* Real round sighash: preimage = [midstate bytes] || RP || (48 dummy pushes minus the 16 selected) || T */
__constant__ uint8_t cRP[64];
__constant__ uint8_t cD48[480];
__constant__ uint8_t cT[1024];
__constant__ int cRPLen, cTLen, cMidBytes;
__constant__ unsigned long long cBin[49][17];
#endif

#define CK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "CUDA %s at %s:%d\n", cudaGetErrorString(e), __FILE__, __LINE__); exit(1); } } while (0)

#include "field2.cuh"

/* ================================================================== sighash (as pool.cu) */
#ifdef ROUND_MODE
__device__ __forceinline__ void sighash_z(uint32_t seq, uint32_t lt, int extra, uint64_t z[4]) {
    (void)extra;
    /* unrank counter -> 16-subset of positions 0..47 (lexicographic) */
    unsigned long long r = ((unsigned long long)seq << 32) | lt;
    unsigned long long sel = 0; int need = 16;
    for (int pos = 0; pos < 48 && need; pos++) {
        unsigned long long c = cBin[47 - pos][need - 1];
        if (r < c) { sel |= 1ull << pos; need--; } else r -= c;
    }
    uint8_t buf[1536];
    int L = 0;
    for (int i = 0; i < cRPLen; i++) buf[L++] = cRP[i];
    for (int pos = 0; pos < 48; pos++)
        if (!((sel >> pos) & 1)) for (int i = 0; i < 10; i++) buf[L++] = cD48[pos * 10 + i];
    for (int i = 0; i < cTLen; i++) buf[L++] = cT[i];
    const uint64_t bits = (uint64_t)(cMidBytes + L) * 8;
    buf[L++] = 0x80;
    while ((L & 63) != 56) buf[L++] = 0;
    for (int i = 0; i < 8; i++) buf[L++] = (bits >> (56 - 8 * i)) & 0xFF;
    uint32_t st[8];
#pragma unroll
    for (int i = 0; i < 8; i++) st[i] = cMid[i];
    for (int b = 0; b < L; b += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[b + 4 * i] << 24) | ((uint32_t)buf[b + 4 * i + 1] << 16) |
                   ((uint32_t)buf[b + 4 * i + 2] << 8) | (uint32_t)buf[b + 4 * i + 3];
        sha256_fast(st, w);
    }
    uint32_t w2[16];
#pragma unroll
    for (int i = 0; i < 8; i++) w2[i] = st[i];
    w2[8] = 0x80000000; for (int i = 9; i < 15; i++) w2[i] = 0; w2[15] = 256;
    uint32_t s2[8]; sha256_init(s2); sha256_fast(s2, w2);
    z[0] = ((uint64_t)s2[6] << 32) | s2[7]; z[1] = ((uint64_t)s2[4] << 32) | s2[5];
    z[2] = ((uint64_t)s2[2] << 32) | s2[3]; z[3] = ((uint64_t)s2[0] << 32) | s2[1];
}
#else
__device__ __forceinline__ void sighash_z(uint32_t seq, uint32_t lt, int extra, uint64_t z[4]) {
    uint32_t st[8];
#pragma unroll
    for (int i = 0; i < 8; i++) st[i] = cMid[i];
    for (int b = 0; b < extra; b++) {
        uint32_t w[16];
#pragma unroll
        for (int i = 0; i < 16; i++) w[i] = cXW[i];
        if (b == 0) w[0] = __byte_perm(lt, 0, 0x0123);
        sha256_fast(st, w);
    }
    uint8_t buf[128];
    for (int i = 0; i < cSufLen; i++) buf[i] = cSuffix[i];
    buf[cSeqOff] = seq; buf[cSeqOff + 1] = seq >> 8; buf[cSeqOff + 2] = seq >> 16; buf[cSeqOff + 3] = seq >> 24;
    buf[cLtOff] = lt; buf[cLtOff + 1] = lt >> 8; buf[cLtOff + 2] = lt >> 16; buf[cLtOff + 3] = lt >> 24;
    buf[cSufLen] = 0x80;
    for (int i = cSufLen + 1; i < 128; i++) buf[i] = 0;
    int nblk = (cSufLen < 56) ? 1 : 2;
    uint64_t bits = (uint64_t)(cTotalLen + extra * 64) * 8;
    int last = nblk * 64 - 8;
    for (int i = 0; i < 8; i++) buf[last + i] = (bits >> (56 - 8 * i)) & 0xFF;
    for (int b = 0; b < nblk; b++) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[b * 64 + i * 4] << 24) | ((uint32_t)buf[b * 64 + i * 4 + 1] << 16) |
                   ((uint32_t)buf[b * 64 + i * 4 + 2] << 8) | (uint32_t)buf[b * 64 + i * 4 + 3];
        sha256_fast(st, w);
    }
    uint32_t w2[16];
#pragma unroll
    for (int i = 0; i < 8; i++) w2[i] = st[i];
    w2[8] = 0x80000000; for (int i = 9; i < 15; i++) w2[i] = 0; w2[15] = 256;
    uint32_t s2[8]; sha256_init(s2); sha256_fast(s2, w2);
    z[0] = ((uint64_t)s2[6] << 32) | s2[7]; z[1] = ((uint64_t)s2[4] << 32) | s2[5];
    z[2] = ((uint64_t)s2[2] << 32) | s2[3]; z[3] = ((uint64_t)s2[0] << 32) | s2[1];
}

#endif /* ROUND_MODE */

/* ================================================================== fixed base, Jacobian */
__device__ __forceinline__ void load_g(uint64_t x[4], uint64_t y[4], const uint8_t *gX, const uint8_t *gY, size_t idx) {
    const uint4 *px = (const uint4 *)(gX + idx), *py = (const uint4 *)(gY + idx);
    uint4 a = __ldg(px), b = __ldg(px + 1), c = __ldg(py), d = __ldg(py + 1);
    x[0] = ((uint64_t)a.y << 32) | a.x; x[1] = ((uint64_t)a.w << 32) | a.z; x[2] = ((uint64_t)b.y << 32) | b.x; x[3] = ((uint64_t)b.w << 32) | b.z;
    y[0] = ((uint64_t)c.y << 32) | c.x; y[1] = ((uint64_t)c.w << 32) | c.z; y[2] = ((uint64_t)d.y << 32) | d.x; y[3] = ((uint64_t)d.w << 32) | d.z;
}

/* (X,Y,Z) += (x2,y2) affine; madd-2007-bl, 8M + 3S. Exceptional cases (equal x) ignored: prob ~2^-256. */
__device__ __forceinline__ void jmadd(uint64_t X[4], uint64_t Y[4], uint64_t Z[4], const uint64_t x2[4], const uint64_t y2[4]) {
    uint64_t z1z1[4], u2[4], s2[4], h[4], hh[4], hhh[4], rr[4], v[4], t[4];
    fsqr(z1z1, Z);
    fmul(u2, x2, z1z1);
    fmul(s2, y2, Z); fmul(s2, s2, z1z1);
    fsub(h, u2, X);
    fsub(rr, s2, Y);
    fsqr(hh, h);
    fmul(hhh, h, hh);
    fmul(v, X, hh);
    fsqr(t, rr); fsub(t, t, hhh); fsub(t, t, v); fsub(X, t, v);     /* X3 = r^2 - HHH - 2V */
    fsub(t, v, X); fmul(t, rr, t);
    fmul(v, Y, hhh); fsub(Y, t, v);                                  /* Y3 = r(V - X3) - Y1*HHH */
    fmul(Z, Z, h);                                                    /* Z3 = Z1*H */
}

__device__ __forceinline__ void fixed_base(uint64_t X[4], uint64_t Y[4], uint64_t Z[4], const uint64_t z[4],
                                           const uint8_t *gX, const uint8_t *gY) {
    const uint16_t *pk = (const uint16_t *)z;
    int c = 0;
    Z[0] = 1; Z[1] = Z[2] = Z[3] = 0;
    for (; c < 16; c++) if (pk[c]) { load_g(X, Y, gX, gY, ((size_t)c * 65536 + (pk[c] - 1)) * 32); c++; break; }
    for (; c < 16; c++) if (pk[c]) {
        uint64_t gx[4], gy[4]; load_g(gx, gy, gX, gY, ((size_t)c * 65536 + (pk[c] - 1)) * 32);
        jmadd(X, Y, Z, gx, gy);
    }
}

/* ================================================================== hashing the three encodings */
__device__ int der_ok(const uint8_t *d, int l) {
    if (l < 9 || d[0] != 0x30 || d[1] + 3 != l) return 0;
    int idx = 2;
    for (int p = 0; p < 2; p++) {
        if (idx >= l - 1 || d[idx] != 0x02) return 0; idx++;
        int il = d[idx]; idx++;
        if (il == 0 || idx + il > l - 1) return 0;
        if (il > 1 && d[idx] == 0 && !(d[idx + 1] & 0x80)) return 0;
        if (d[idx] & 0x80) return 0; idx += il;
    }
    return idx == l - 1;
}

/* first big-endian output word, plus gate */
template <int HASH, int GATE>
__device__ __forceinline__ int gate_sha(const uint32_t hs[8], uint32_t *w0) {
    *w0 = hs[0];
    if (!GATE) { uint32_t lz = hs[0] ? __clz(hs[0]) : 32 + __clz(hs[1]); return lz >= (uint32_t)cZeros; }
    if ((hs[0] >> 24) != 0x30) return 0;
    uint8_t h[32];
    for (int i = 0; i < 8; i++) { h[4*i] = hs[i] >> 24; h[4*i+1] = hs[i] >> 16; h[4*i+2] = hs[i] >> 8; h[4*i+3] = hs[i]; }
    return der_ok(h, 32);
}
template <int GATE>
__device__ __forceinline__ int gate_rmd(const uint32_t s[5], uint32_t *w0) {
    uint32_t a = __byte_perm(s[0], 0, 0x0123);
    *w0 = a;
    if (!GATE) { uint32_t b = __byte_perm(s[1], 0, 0x0123); uint32_t lz = a ? __clz(a) : 32 + __clz(b); return lz >= (uint32_t)cZeros; }
    if ((a >> 24) != 0x30) return 0;
    uint8_t h[20];
    for (int i = 0; i < 5; i++) { h[4*i] = s[i]; h[4*i+1] = s[i] >> 8; h[4*i+2] = s[i] >> 16; h[4*i+3] = s[i] >> 24; }
    return der_ok(h, 20);
}

/* hash (prefix || X || Y) for enc 0 (33 B, prefix 02|par), 1 (65 B, 04), 2 (65 B, 06|par).
 * X, Y canonical. Returns gate bitmask over encodings; w0 receives each first hash word. */
template <int HASH, int GATE, int ENC>
__device__ __forceinline__ int shots(const uint64_t X[4], const uint64_t Y[4], uint32_t w0[3]) {
    const uint32_t *x32 = (const uint32_t *)X, *y32 = (const uint32_t *)Y;
    uint32_t S[16];                          /* big-endian words of X||Y */
#pragma unroll
    for (int k = 0; k < 8; k++) { S[k] = x32[7 - k]; S[8 + k] = y32[7 - k]; }
    const uint32_t par = y32[0] & 1;
    int mask = 0;
#pragma unroll
    for (int e = 0; e < ENC; e++) {
        const uint32_t pfx = e == 0 ? 2 + par : (e == 1 ? 4 : 6 + par);
        uint32_t w[16];
        w[0] = (pfx << 24) | (S[0] >> 8);
        if (e == 0) {
#pragma unroll
            for (int i = 1; i < 8; i++) w[i] = (S[i - 1] << 24) | (S[i] >> 8);
            w[8] = (S[7] << 24) | 0x00800000u;
#pragma unroll
            for (int i = 9; i < 16; i++) w[i] = 0;
            if (HASH == 0) w[15] = 33 * 8; else w[14] = 33 * 8;
        } else {
#pragma unroll
            for (int i = 1; i < 16; i++) w[i] = (S[i - 1] << 24) | (S[i] >> 8);
        }
        if (HASH == 0) {
            uint32_t hs[8]; sha256_init(hs); sha256_fast(hs, w);
            if (e) {
                uint32_t w2[16];
                w2[0] = (S[15] << 24) | 0x00800000u;
#pragma unroll
                for (int i = 1; i < 16; i++) w2[i] = 0;
                w2[15] = 65 * 8;
                sha256_fast(hs, w2);
            }
            if (gate_sha<HASH, GATE>(hs, &w0[e])) mask |= 1 << e;
        } else {
#pragma unroll
            for (int i = 0; i < 16; i++) w[i] = __byte_perm(w[i], 0, 0x0123);
            if (e == 0) { w[14] = 33 * 8; w[15] = 0; }
            uint32_t s[5]; ripemd160_init(s); ripemd160_fast(s, w);
            if (e) {
                uint32_t w2[16];
                w2[0] = __byte_perm((S[15] << 24) | 0x00800000u, 0, 0x0123);
#pragma unroll
                for (int i = 1; i < 16; i++) w2[i] = 0;
                w2[14] = 65 * 8;
                ripemd160_fast(s, w2);
            }
            if (gate_rmd<GATE>(s, &w0[e])) mask |= 1 << e;
        }
    }
    return mask;
}

/* ================================================================== kernel */
template <int HASH, int GATE, int ENC>
__global__ void __launch_bounds__(128) pool2_kernel(uint32_t seq, uint32_t lt_base, int extra, int K, int MZ,
        const uint8_t *gtX, const uint8_t *gtY, uint32_t *hit_cnt, uint32_t *hits, uint32_t max_hits, uint64_t *dbg) {
    const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t lt0 = lt_base + tid * MZ;
    uint64_t bx[MZMAX][4], by[MZMAX][4];
    uint64_t pre[BMAX][4];

    /* setup: B_m = z_m * G in Jacobian, then one batched inversion of the Z's */
    for (int m = 0; m < MZ; m++) {
        uint64_t z[4], Z[4];
        sighash_z(seq, lt0 + m, extra, z);
        fixed_base(bx[m], by[m], Z, z, gtX, gtY);
        if (m == 0) fcopy(pre[0], Z); else fmul(pre[m], pre[m - 1], Z);
        fcopy(pre[BMAX - 1 - m], Z);                        /* stash Z at the top end of pre */
    }
    {
        uint64_t inv[4]; finv(inv, pre[MZ - 1]);
        for (int m = MZ - 1; m >= 0; m--) {
            uint64_t zi[4], zi2[4], Z[4];
            fcopy(Z, pre[BMAX - 1 - m]);
            if (m) fmul(zi, inv, pre[m - 1]); else fcopy(zi, inv);
            fmul(inv, inv, Z);
            fsqr(zi2, zi);
            fmul(bx[m], bx[m], zi2); fcanon(bx[m]);
            fmul(zi2, zi2, zi); fmul(by[m], by[m], zi2); fcanon(by[m]);
        }
    }

    /* pool: prefix products of dx_i = x_{jA} - x_B over i = m*K + j */
    const int n = MZ * K;
    {
        uint64_t acc[4] = {1, 0, 0, 0};
        int i = 0;
        for (int m = 0; m < MZ; m++)
            for (int j = 0; j < K; j++, i++) {
                uint64_t jx[4] = {cJX[j][0], cJX[j][1], cJX[j][2], cJX[j][3]}, dx[4];
                fsub(dx, jx, bx[m]);
                if (i == 0) fcopy(acc, dx); else fmul(acc, acc, dx);
                fcopy(pre[i], acc);
            }
    }
    uint64_t inv[4]; finv(inv, pre[n - 1]);
    int i = n - 1;
    for (int m = MZ - 1; m >= 0; m--)
    for (int j = K - 1; j >= 0; j--, i--) {
        uint64_t jx[4] = {cJX[j][0], cJX[j][1], cJX[j][2], cJX[j][3]};
        uint64_t jy[4] = {cJY[j][0], cJY[j][1], cJY[j][2], cJY[j][3]};
        uint64_t dx[4], invi[4];
        fsub(dx, jx, bx[m]);
        if (i) fmul(invi, inv, pre[i - 1]); else fcopy(invi, inv);
        fmul(inv, inv, dx);
#pragma unroll
        for (int sg = 0; sg < 2; sg++) {
            /* Q = -B + (sg ? -jA : jA);  lambda = (yP + yB) / (xP - xB) */
            uint64_t yP[4], lam[4], x3[4], y3[4], t[4];
#if defined(ABL_NOEC)            /* ablation: hash + loop only; x3/y3 cheap stand-ins derived from the batch */
            fcopy(x3, invi); x3[0] ^= sg; fcopy(y3, bx[m]); y3[0] ^= j;
            if (0) {
#else
            if (1) {
#endif
            if (sg) { uint64_t zero[4] = {0, 0, 0, 0}; fsub(yP, zero, jy); } else fcopy(yP, jy);
            fadd(t, yP, by[m]);
            fmul(lam, t, invi);
            fsqr(x3, lam); fsub(x3, x3, bx[m]); fsub(x3, x3, jx);
            fsub(t, bx[m], x3); fmul(y3, t, lam); fadd(y3, y3, by[m]);
            }
            fcanon(x3); fcanon(y3);
            uint32_t w0[3] = {0, 0, 0};
#if defined(ABL_NOHASH)          /* ablation: EC + loop only; gate on x bits so work is not optimized away */
            int mask = ((uint32_t)(x3[3] >> 32) >> (32 - cZeros)) == 0 ? 1 : 0;
#else
            int mask = shots<HASH, GATE, ENC>(x3, y3, w0);
#endif
            if (dbg && tid == 0 && m == 0) {
                uint64_t *o = dbg + (2 * j + sg) * 12;
                for (int q = 0; q < 4; q++) { o[q] = x3[q]; o[4 + q] = y3[q]; }
                for (int e = 0; e < ENC; e++) o[8 + e] = w0[e];
            }
            while (mask) {
                int e = __ffs(mask) - 1; mask &= mask - 1;
                uint32_t pos = atomicAdd(hit_cnt, 1);
                if (pos < max_hits) {
                    hits[4 * pos] = seq; hits[4 * pos + 1] = lt0 + m;
                    hits[4 * pos + 2] = j + 1; hits[4 * pos + 3] = sg | (e << 1);
                }
            }
        }
    }
}

/* ================================================================== host */
static void bn_to_le(const BIGNUM *b, uint8_t out[32]) {
    uint8_t be[32] = {0}; BN_bn2bin(b, be + (32 - BN_num_bytes(b)));
    for (int i = 0; i < 32; i++) out[i] = be[31 - i];
}

static void compute_gtable(uint8_t *gX, uint8_t *gY) {
    const size_t bytes = 16ULL * 65536 * 32;
    const char *cache = "/tmp/pool_gtable_le.bin";
    FILE *f = fopen(cache, "rb");
    if (f) {
        size_t a = fread(gX, 1, bytes, f), b = fread(gY, 1, bytes, f); fclose(f);
        if (a == bytes && b == bytes) { fprintf(stderr, "gtable: cache hit\n"); return; }
    }
    fprintf(stderr, "gtable: computing 16 x 65535 points (OpenMP)...\n");
#pragma omp parallel for schedule(dynamic)
    for (int ch = 0; ch < 16; ch++) {
        EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *x = BN_new(), *y = BN_new(), *sh = BN_new();
        EC_POINT *base = EC_POINT_new(grp), *pt = EC_POINT_new(grp);
        BN_one(sh); BN_lshift(sh, sh, 16 * ch);
        EC_POINT_mul(grp, base, sh, NULL, NULL, ctx);
        EC_POINT_copy(pt, base);
        for (int i = 0; i < 65535; i++) {
            EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, ctx);
            size_t off = ((size_t)ch * 65536 + i) * 32;
            bn_to_le(x, gX + off); bn_to_le(y, gY + off);
            EC_POINT_add(grp, pt, pt, base, ctx);
        }
        BN_free(x); BN_free(y); BN_free(sh); EC_POINT_free(base); EC_POINT_free(pt);
        BN_CTX_free(ctx); EC_GROUP_free(grp);
    }
    f = fopen(cache, "wb");
    if (f) { fwrite(gX, 1, bytes, f); fwrite(gY, 1, bytes, f); fclose(f); }
}

static void compute_jA(int K) {
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *one = BN_new(), *j = BN_new(), *x = BN_new(), *y = BN_new();
    EC_POINT *A = EC_POINT_new(grp), *P = EC_POINT_new(grp);
    BN_one(one);
    if (!EC_POINT_set_compressed_coordinates_GFp(grp, A, one, 0, ctx)) { fprintf(stderr, "x=1 not on curve?\n"); exit(1); }
    static uint64_t hx[KMAX][4], hy[KMAX][4];
    for (int i = 1; i <= K; i++) {
        BN_set_word(j, i);
        EC_POINT_mul(grp, P, NULL, A, j, ctx);
        EC_POINT_get_affine_coordinates_GFp(grp, P, x, y, ctx);
        bn_to_le(x, (uint8_t *)hx[i - 1]); bn_to_le(y, (uint8_t *)hy[i - 1]);
    }
    CK(cudaMemcpyToSymbol(cJX, hx, sizeof hx)); CK(cudaMemcpyToSymbol(cJY, hy, sizeof hy));
    EC_POINT_free(A); EC_POINT_free(P); BN_free(one); BN_free(j); BN_free(x); BN_free(y);
    BN_CTX_free(ctx); EC_GROUP_free(grp);
}

typedef void (*launch_fn)(dim3, dim3, uint32_t, uint32_t, int, int, int, const uint8_t *, const uint8_t *,
                          uint32_t *, uint32_t *, uint32_t, uint64_t *);
template <int HASH, int GATE, int ENC>
static void launch(dim3 g, dim3 b, uint32_t seq, uint32_t lt, int extra, int K, int MZ, const uint8_t *gx,
                   const uint8_t *gy, uint32_t *hc, uint32_t *h, uint32_t mh, uint64_t *dbg) {
    pool2_kernel<HASH, GATE, ENC><<<g, b>>>(seq, lt, extra, K, MZ, gx, gy, hc, h, mh, dbg);
}
static launch_fn pick(int hash, int gate, int enc) {
    static launch_fn T[2][2][2] = {
        {{launch<0, 0, 1>, launch<0, 0, 3>}, {launch<0, 1, 1>, launch<0, 1, 3>}},
        {{launch<1, 0, 1>, launch<1, 0, 3>}, {launch<1, 1, 1>, launch<1, 1, 3>}}};
    return T[hash][gate][enc == 3];
}

static double now() { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + 1e-9 * t.tv_nsec; }

int main(int argc, char **argv) {
    if (argc < 9) { fprintf(stderr, "usage: %s pinning.bin K sha|rmd zeros|der N seconds extra_blocks hits_out [enc] [seq]\n", argv[0]); return 1; }
    int K = atoi(argv[2]), hash = !strcmp(argv[3], "rmd"), gate = !strcmp(argv[4], "der"), N = atoi(argv[5]);
    double seconds = atof(argv[6]); int extra = atoi(argv[7]); const char *hits_out = argv[8];
    int enc = argc > 9 ? atoi(argv[9]) : 3;
    uint32_t seq = argc > 10 ? (uint32_t)strtoul(argv[10], 0, 0) : 0x12345678u;
    if (K < 1 || K > KMAX || (enc != 1 && enc != 3)) { fprintf(stderr, "bad K/enc\n"); return 1; }
    int MZ = BMAX / K; if (MZ > MZMAX) MZ = MZMAX; if (MZ < 1) MZ = 1;
    if (getenv("POOL_MZ")) MZ = atoi(getenv("POOL_MZ"));
    int TPB = getenv("POOL_TPB") ? atoi(getenv("POOL_TPB")) : 128;

    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("bin"); return 1; }
    static uint8_t raw[16384]; size_t nr = fread(raw, 1, sizeof raw, f); fclose(f); (void)nr;
#ifdef ROUND_MODE
    {   /* round.bin: "RND1" | 8 x BE u32 midstate | u32 midBytes | u32 rpLen | 64 B rp | 480 B d48 | u32 tLen | tLen B | 49*17 u64 */
        if (memcmp(raw, "RND1", 4)) { fprintf(stderr, "not a round problem\n"); return 1; }
        uint32_t mid[8]; for (int i = 0; i < 8; i++) mid[i] = (raw[4+4*i] << 24) | (raw[5+4*i] << 16) | (raw[6+4*i] << 8) | raw[7+4*i];
        int q = 36; int midB = *(uint32_t *)(raw + q); q += 4; int rpLen = *(uint32_t *)(raw + q); q += 4;
        CK(cudaMemcpyToSymbol(cRP, raw + q, 64)); q += 64;
        CK(cudaMemcpyToSymbol(cD48, raw + q, 480)); q += 480;
        int tLen = *(uint32_t *)(raw + q); q += 4;
        static uint8_t tb[1024] = {0}; memcpy(tb, raw + q, tLen); q += tLen;
        CK(cudaMemcpyToSymbol(cT, tb, 1024));
        CK(cudaMemcpyToSymbol(cBin, raw + q, 49 * 17 * 8));
        CK(cudaMemcpyToSymbol(cMid, mid, 32)); CK(cudaMemcpyToSymbol(cRPLen, &rpLen, 4));
        CK(cudaMemcpyToSymbol(cTLen, &tLen, 4)); CK(cudaMemcpyToSymbol(cMidBytes, &midB, 4));
        CK(cudaMemcpyToSymbol(cZeros, &N, 4));
        fprintf(stderr, "round mode: midBytes=%d rp=%d t=%d\n", midB, rpLen, tLen);
    }
    if (0)
#endif
    {
    uint32_t mid[8]; for (int i = 0; i < 8; i++) mid[i] = (raw[4*i] << 24) | (raw[4*i+1] << 16) | (raw[4*i+2] << 8) | raw[4*i+3];
    int p = 32, sufLen = *(uint32_t *)(raw + p); p += 4;
    uint8_t suf[128] = {0}; memcpy(suf, raw + p, sufLen); p += sufLen;
    int total = *(uint32_t *)(raw + p), seqOff = *(uint32_t *)(raw + p + 4), ltOff = *(uint32_t *)(raw + p + 8);
    uint32_t xw[16]; for (int i = 0; i < 16; i++) { uint8_t b4[4]; for (int k = 0; k < 4; k++) b4[k] = (uint8_t)((4 * i + k) * 7 + 13);
        xw[i] = (b4[0] << 24) | (b4[1] << 16) | (b4[2] << 8) | b4[3]; }
    CK(cudaMemcpyToSymbol(cMid, mid, 32)); CK(cudaMemcpyToSymbol(cSuffix, suf, 128));
    CK(cudaMemcpyToSymbol(cSufLen, &sufLen, 4)); CK(cudaMemcpyToSymbol(cSeqOff, &seqOff, 4));
    CK(cudaMemcpyToSymbol(cLtOff, &ltOff, 4)); CK(cudaMemcpyToSymbol(cTotalLen, &total, 4));
    CK(cudaMemcpyToSymbol(cZeros, &N, 4)); CK(cudaMemcpyToSymbol(cXW, xw, 64));
    }

    const size_t gtb = 16ULL * 65536 * 32;
    uint8_t *hX = (uint8_t *)malloc(gtb), *hY = (uint8_t *)malloc(gtb);
    compute_gtable(hX, hY);
    uint8_t *gX, *gY; CK(cudaMalloc(&gX, gtb)); CK(cudaMalloc(&gY, gtb));
    CK(cudaMemcpy(gX, hX, gtb, cudaMemcpyHostToDevice)); CK(cudaMemcpy(gY, hY, gtb, cudaMemcpyHostToDevice));
    compute_jA(K);

    const uint32_t MAXH = 1 << 20;
    uint32_t *dHC, *dH; CK(cudaMalloc(&dHC, 4)); CK(cudaMalloc(&dH, 16 * MAXH)); CK(cudaMemset(dHC, 0, 4));
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop, 0));
    int blocksPerSM = getenv("POOL_BPS") ? atoi(getenv("POOL_BPS")) : 8;
    dim3 block(TPB), grid(prop.multiProcessorCount * blocksPerSM);
    uint32_t per_launch = grid.x * block.x * MZ;
    launch_fn fn = pick(hash, gate, enc);

    if (getenv("POOL_DUMP")) {
        size_t nb = 8 * 12 * 2 * K;
        uint64_t *dD; CK(cudaMalloc(&dD, nb)); CK(cudaMemset(dD, 0, nb));
        fn(grid, block, seq, 0, extra, K, MZ, gX, gY, dHC, dH, MAXH, dD); CK(cudaGetLastError()); CK(cudaDeviceSynchronize());
        uint64_t *hD = (uint64_t *)malloc(nb); CK(cudaMemcpy(hD, dD, nb, cudaMemcpyDeviceToHost));
        for (int i = 0; i < 2 * K; i++) {
            uint64_t *o = hD + 12 * i;
            printf("DUMP2 %u 0 %d %d %016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx", seq, i / 2 + 1, i % 2,
                   (unsigned long long)o[3], (unsigned long long)o[2], (unsigned long long)o[1], (unsigned long long)o[0],
                   (unsigned long long)o[7], (unsigned long long)o[6], (unsigned long long)o[5], (unsigned long long)o[4]);
            for (int e = 0; e < enc; e++) printf(" %08llx", (unsigned long long)o[8 + e]);
            printf("\n");
        }
        return 0;
    }

    fn(grid, block, seq, 0x40000000u, extra, K, MZ, gX, gY, dHC, dH, MAXH, nullptr);   /* warm-up */
    CK(cudaGetLastError()); CK(cudaDeviceSynchronize()); CK(cudaMemset(dHC, 0, 4));
    uint32_t lt = 0; uint64_t cand = 0; double t0 = now(), t1;
    while ((t1 = now()) - t0 < seconds) {
        for (int r = 0; r < 4; r++) {
            if ((uint64_t)lt + per_launch > 0xFFFFFFFFull) { seq++; lt = 0; }
            fn(grid, block, seq, lt, extra, K, MZ, gX, gY, dHC, dH, MAXH, nullptr); lt += per_launch; cand += per_launch;
        }
        CK(cudaGetLastError()); CK(cudaDeviceSynchronize());
        if (getenv("POOL_STOP_ON_HIT")) {
            uint32_t hc_; CK(cudaMemcpy(&hc_, dHC, 4, cudaMemcpyDeviceToHost));
            if (hc_) break;
            static double last = 0; double tn = now();
            if (tn - last > 60) { last = tn; fprintf(stderr, "[%.0f s] candidates %llu shots %.3e\n", tn - t0,
                (unsigned long long)cand, (double)cand * 2 * K * enc); }
        }
    }
    t1 = now();
    uint32_t hc; CK(cudaMemcpy(&hc, dHC, 4, cudaMemcpyDeviceToHost));
    uint32_t keep = hc < MAXH ? hc : MAXH;
    uint32_t *hh = (uint32_t *)malloc(16 * (size_t)keep + 16);
    CK(cudaMemcpy(hh, dH, 16 * (size_t)keep, cudaMemcpyDeviceToHost));
    FILE *o = fopen(hits_out, "w");
    for (uint32_t i = 0; i < keep; i++) fprintf(o, "%u %u %u %u %u\n", hh[4*i], hh[4*i+1], hh[4*i+2], hh[4*i+3] & 1, hh[4*i+3] >> 1);
    fclose(o);
    double el = t1 - t0, shots_ = (double)cand * 2 * K * enc;
    printf("{\"kernel\":\"pool2\",\"gpu\":\"%s\",\"K\":%d,\"MZ\":%d,\"enc\":%d,\"tpb\":%d,\"hash\":\"%s\",\"gate\":\"%s\",\"N\":%d,"
           "\"extra_blocks\":%d,\"seconds\":%.2f,\"candidates\":%llu,\"z_per_s\":%.4e,\"shots_per_s\":%.4e,\"hits\":%u,"
           "\"expected_hits\":%.1f}\n",
           prop.name, K, MZ, enc, TPB, hash ? "rmd" : "sha", gate ? "der" : "zeros", N, extra, el,
           (unsigned long long)cand, cand / el, shots_ / el, hc, gate ? 0.0 : shots_ / (double)(1ULL << N));
    return 0;
}
