/* pool.cu -- GPU prototype of the QSB nonce-signature pool (research/QSB_IMPROVEMENTS.md, section 2).
 *
 * Per candidate (sequence, locktime):
 *   z = SHA256d(prefix || [extra round-shape blocks] || suffix(seq, lt))      (pinning-style midstate)
 *   B = z*G                            (16 x 16-bit window fixed-base table, projective, batch-inverted)
 *   for j = 1..K, sign in {+,-}:   Q = sign*j*A - B     (A = R for r = 1; j*A from __constant__ memory)
 *        one Montgomery-batched inversion per thread covers every (candidate, j) x-difference;
 *        the +j and -j points share it.
 *   h = HASH(compressed Q), test the gate.
 * K = 1 is the control: structurally today's per-candidate recovery (one scalar mult, 2 shots).
 *
 * Gate: leading-zero bits >= N (hits are verifiable on CPU, verify_pool_hits.py) or the real strict-DER
 * predicate (throughput only; 2^-46 hits). Hash: SHA-256 (as the Layr benchmark) or RIPEMD-160 (as QSB).
 *
 * Field/SHA/RIPEMD primitives: VanitySearch GPUMath.h / GPUHash.h (GPLv3, see COPYING), as in the
 * QSB seed kernels. This file is research code, GPLv3 as a derived work.
 *
 * Build: nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -o pool pool.cu -lcrypto -lgomp
 * Run:   ./pool <pinning.bin> <K> <sha|rmd> <zeros|der> <N> <seconds> <extra_blocks> <hits_out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>
#include "GPUMath.h"
/* definitions GPUHash.h (CudaBrainSecp) expects, copied from the QSB seed kernel */
#define MAX_LEN_WORD_PRIME 20
#define MAX_LEN_WORD_AFFIX 4
#define AFFIX_IS_SUFFIX true
#define SIZE_COMBO_MULTI 4
#define COUNT_COMBO_SYMBOLS 100
#define IDX_CUDA_THREAD ((blockIdx.x * blockDim.x) + threadIdx.x)

__device__ __constant__ int MULTI_EIGHT[65] = { 0,
    0+8,0+16,0+24,0+32,0+40,0+48,0+56,0+64,
    64+8,64+16,64+24,64+32,64+40,64+48,64+56,64+64,
    128+8,128+16,128+24,128+32,128+40,128+48,128+56,128+64,
    192+8,192+16,192+24,192+32,192+40,192+48,192+56,192+64,
    256+8,256+16,256+24,256+32,256+40,256+48,256+56,256+64,
    320+8,320+16,320+24,320+32,320+40,320+48,320+56,320+64,
    384+8,384+16,384+24,384+32,384+40,384+48,384+56,384+64,
    448+8,448+16,448+24,448+32,448+40,448+48,448+56,448+64,
};
__device__ __constant__ uint8_t COMBO_SYMBOLS[100] = {
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
    0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x5B,0x5C,0x5D,0x5E,0x5F,0x60,0x7B,0x7C,0x7D,0x7E,
    0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,
    0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,
    0x00,0x7F,0xFF,0x09,0x0D
};
#include "GPUHash.h"

extern "C" {
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
}

#define KMAX 128
__constant__ uint32_t cMid[8];
__constant__ uint8_t cSuffix[128];
__constant__ int cSufLen, cSeqOff, cLtOff, cTotalLen, cZeros;
__constant__ uint32_t cXW[16];
__constant__ uint64_t cJX[KMAX][4], cJY[KMAX][4];

#define CK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "CUDA %s at %s:%d\n", cudaGetErrorString(e), __FILE__, __LINE__); exit(1); } } while (0)

/* ------------------------------------------------------------------ sighash */
__device__ __forceinline__ void sighash_z(uint32_t seq, uint32_t lt, int extra, uint64_t z[4]) {
    uint32_t st[8];
#pragma unroll
    for (int i = 0; i < 8; i++) st[i] = cMid[i];
    for (int b = 0; b < extra; b++) {                 /* round shape: rehash extra variable blocks */
        uint32_t w[16];
#pragma unroll
        for (int i = 0; i < 16; i++) w[i] = cXW[i];
        if (b == 0) w[0] = __byte_perm(lt, 0, 0x0123);
        _SHA256Transform(st, w);
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
        _SHA256Transform(st, w);
    }
    uint32_t w2[16];
#pragma unroll
    for (int i = 0; i < 8; i++) w2[i] = st[i];
    w2[8] = 0x80000000; for (int i = 9; i < 15; i++) w2[i] = 0; w2[15] = 256;
    uint32_t s2[8]; _SHA256Initialize(s2); _SHA256Transform(s2, w2);
    z[0] = ((uint64_t)s2[6] << 32) | s2[7]; z[1] = ((uint64_t)s2[4] << 32) | s2[5];
    z[2] = ((uint64_t)s2[2] << 32) | s2[3]; z[3] = ((uint64_t)s2[0] << 32) | s2[1];
}

/* ------------------------------------------------------------------ fixed-base z*G (projective, no inversion) */
__device__ __forceinline__ void fixed_base(uint64_t qx[4], uint64_t qy[4], uint64_t qz[5], const uint64_t z[4],
                                           const uint8_t *gtX, const uint8_t *gtY) {
    uint16_t pk[16]; memcpy(pk, z, 32);
    qz[0] = 1; qz[1] = qz[2] = qz[3] = qz[4] = 0;
    int c = 0;
    for (; c < 16; c++) if (pk[c]) {
        size_t idx = ((size_t)c * 65536 + (pk[c] - 1)) * 32;
        memcpy(qx, gtX + idx, 32); memcpy(qy, gtY + idx, 32); c++; break;
    }
    for (; c < 16; c++) if (pk[c]) {
        uint64_t gx[4], gy[4]; size_t idx = ((size_t)c * 65536 + (pk[c] - 1)) * 32;
        memcpy(gx, gtX + idx, 32); memcpy(gy, gtY + idx, 32);
        _PointAddSecp256k1(qx, qy, qz, gx, gy);
    }
}

/* in-place Montgomery batch inversion of v[0..n-1]; pre is scratch */
template <int NMAX>
__device__ __forceinline__ void batch_inv(uint64_t v[NMAX][4], uint64_t pre[NMAX][4], int n) {
    Load256(pre[0], v[0]);
    for (int i = 1; i < n; i++) _ModMult(pre[i], pre[i - 1], v[i]);
    uint64_t inv[5]; Load256(inv, pre[n - 1]); inv[4] = 0; _ModInv(inv);
    for (int i = n - 1; i > 0; i--) {
        uint64_t t[4]; _ModMult(t, inv, pre[i - 1]); _ModMult(inv, v[i]); Load256(v[i], t);
    }
    Load256(v[0], inv);
}

__device__ int der_ok(const uint8_t *d, int l) {          /* BIP66 IsValidSignatureEncoding */
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

/* hash compressed (x, parity) and apply the gate */
template <int HASH, int DER>
__device__ __forceinline__ int shot(const uint64_t x[4], int parity) {
    const uint32_t *x32 = (const uint32_t *)x;
    uint32_t pb[16];
    pb[0] = __byte_perm(x32[7], 0x2 + parity, 0x4321);
    pb[1] = __byte_perm(x32[7], x32[6], 0x0765); pb[2] = __byte_perm(x32[6], x32[5], 0x0765);
    pb[3] = __byte_perm(x32[5], x32[4], 0x0765); pb[4] = __byte_perm(x32[4], x32[3], 0x0765);
    pb[5] = __byte_perm(x32[3], x32[2], 0x0765); pb[6] = __byte_perm(x32[2], x32[1], 0x0765);
    pb[7] = __byte_perm(x32[1], x32[0], 0x0765); pb[8] = __byte_perm(x32[0], 0x80, 0x0456);
    if (HASH == 0) {
        for (int i = 9; i < 15; i++) pb[i] = 0; pb[15] = 0x108;
        uint32_t hs[8]; _SHA256Initialize(hs); _SHA256Transform(hs, pb);
        if (!DER) {
            uint32_t lz = hs[0] ? __clz(hs[0]) : 32 + __clz(hs[1]);
            return lz >= (uint32_t)cZeros;
        }
        uint8_t h[32];
        for (int i = 0; i < 8; i++) { h[4 * i] = hs[i] >> 24; h[4 * i + 1] = hs[i] >> 16; h[4 * i + 2] = hs[i] >> 8; h[4 * i + 3] = hs[i]; }
        return der_ok(h, 32);
    } else {
        uint32_t w[16];
        for (int i = 0; i < 9; i++) w[i] = __byte_perm(pb[i], 0, 0x0123);
        for (int i = 9; i < 16; i++) w[i] = 0; w[14] = 33 * 8;
        uint32_t s[5]; _RIPEMD160Initialize(s); _RIPEMD160Transform(s, w);
        if (!DER) {
            uint32_t a = __byte_perm(s[0], 0, 0x0123), b = __byte_perm(s[1], 0, 0x0123);
            uint32_t lz = a ? __clz(a) : 32 + __clz(b);
            return lz >= (uint32_t)cZeros;
        }
        uint8_t h[20];
        for (int i = 0; i < 5; i++) { h[4 * i] = s[i]; h[4 * i + 1] = s[i] >> 8; h[4 * i + 2] = s[i] >> 16; h[4 * i + 3] = s[i] >> 24; }
        return der_ok(h, 20);
    }
}

template <int HASH>
__device__ uint32_t shot_word(const uint64_t x[4], int parity) {   /* debug: first 4 hash bytes, big-endian */
    const uint32_t *x32 = (const uint32_t *)x;
    uint32_t pb[16];
    pb[0] = __byte_perm(x32[7], 0x2 + parity, 0x4321);
    pb[1] = __byte_perm(x32[7], x32[6], 0x0765); pb[2] = __byte_perm(x32[6], x32[5], 0x0765);
    pb[3] = __byte_perm(x32[5], x32[4], 0x0765); pb[4] = __byte_perm(x32[4], x32[3], 0x0765);
    pb[5] = __byte_perm(x32[3], x32[2], 0x0765); pb[6] = __byte_perm(x32[2], x32[1], 0x0765);
    pb[7] = __byte_perm(x32[1], x32[0], 0x0765); pb[8] = __byte_perm(x32[0], 0x80, 0x0456);
    if (HASH == 0) {
        for (int i = 9; i < 15; i++) pb[i] = 0; pb[15] = 0x108;
        uint32_t hs[8]; _SHA256Initialize(hs); _SHA256Transform(hs, pb); return hs[0];
    }
    uint32_t w[16];
    for (int i = 0; i < 9; i++) w[i] = __byte_perm(pb[i], 0, 0x0123);
    for (int i = 9; i < 16; i++) w[i] = 0; w[14] = 33 * 8;
    uint32_t s[5]; _RIPEMD160Initialize(s); _RIPEMD160Transform(s, w);
    return __byte_perm(s[0], 0, 0x0123);
}

/* ------------------------------------------------------------------ kernel */
template <int K, int MZ, int HASH, int DER>
__global__ void __launch_bounds__(128) pool_kernel(uint32_t seq, uint32_t lt_base, int extra,
        const uint8_t *gtX, const uint8_t *gtY, uint32_t *hit_cnt, uint32_t *hits, uint32_t max_hits,
        uint64_t *dbg) {
    const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t lt0 = lt_base + tid * MZ;
    uint64_t bx[MZ][4], by[MZ][4];
    uint64_t bzv[MZ][4], bzp[MZ][4];
    for (int m = 0; m < MZ; m++) {
        uint64_t z[4], qz[5];
        sighash_z(seq, lt0 + m, extra, z);
        fixed_base(bx[m], by[m], qz, z, gtX, gtY);
        Load256(bzv[m], qz);
    }
    batch_inv<MZ>(bzv, bzp, MZ);
    for (int m = 0; m < MZ; m++) { _ModMult(bx[m], bzv[m]); _ModMult(by[m], bzv[m]); }

    uint64_t dx[MZ * K][4], pre[MZ * K][4];
    for (int m = 0; m < MZ; m++)
        for (int j = 0; j < K; j++) {
            uint64_t jx[4] = {cJX[j][0], cJX[j][1], cJX[j][2], cJX[j][3]};
            _ModSub256(dx[m * K + j], jx, bx[m]);
        }
    batch_inv<MZ * K>(dx, pre, MZ * K);

#ifdef NO_OUTER_UNROLL
#pragma unroll 1
#endif
    for (int m = 0; m < MZ; m++)
#ifdef NO_OUTER_UNROLL
#pragma unroll 1
#endif
        for (int j = 0; j < K; j++) {
            uint64_t jx[4] = {cJX[j][0], cJX[j][1], cJX[j][2], cJX[j][3]};
            uint64_t jy[4] = {cJY[j][0], cJY[j][1], cJY[j][2], cJY[j][3]};
#pragma unroll
            for (int sg = 0; sg < 2; sg++) {
                /* Q = -B + sg? -jA : +jA ;  lambda = (yP + yB) / (xP - xB) */
                uint64_t yP[4], lam[4], x3[4], y3[4], t[4];
                if (sg) _ModNeg256(yP, jy); else Load256(yP, jy);
                _ModAdd256(t, yP, by[m]);
                _ModMult(lam, t, dx[m * K + j]);
                _ModSqr(x3, lam);
                _ModSub256(x3, x3, bx[m]);
                _ModSub256(x3, x3, jx);
                _ModSub256(t, bx[m], x3);
                _ModMult(y3, t, lam);
                _ModAdd256(y3, y3, by[m]);
                if (dbg && tid == 0 && m == 0) {
                    uint64_t *o = dbg + (2 * j + sg) * 6;
                    o[0] = x3[0]; o[1] = x3[1]; o[2] = x3[2]; o[3] = x3[3]; o[4] = y3[0] & 1;
                    o[5] = shot_word<HASH>(x3, (int)(y3[0] & 1));
                }
                if (shot<HASH, DER>(x3, (int)(y3[0] & 1))) {
                    uint32_t pos = atomicAdd(hit_cnt, 1);
                    if (pos < max_hits) {
                        hits[4 * pos] = seq; hits[4 * pos + 1] = lt0 + m;
                        hits[4 * pos + 2] = j + 1; hits[4 * pos + 3] = sg;
                    }
                }
            }
        }
}

/* ------------------------------------------------------------------ host */
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

typedef void (*launch_fn)(dim3, dim3, uint32_t, uint32_t, int, const uint8_t *, const uint8_t *, uint32_t *, uint32_t *, uint32_t, uint64_t *);

template <int K, int MZ, int HASH, int DER>
static void launch(dim3 g, dim3 b, uint32_t seq, uint32_t lt, int extra, const uint8_t *gx, const uint8_t *gy,
                   uint32_t *hc, uint32_t *h, uint32_t mh, uint64_t *dbg) {
    pool_kernel<K, MZ, HASH, DER><<<g, b>>>(seq, lt, extra, gx, gy, hc, h, mh, dbg);
}

#define MZ_FOR(K) ((K) == 1 ? 32 : ((64 / (K)) < 1 ? 1 : (64 / (K))))
#define ENTRY(K) { K, MZ_FOR(K), { { launch<K, MZ_FOR(K), 0, 0>, launch<K, MZ_FOR(K), 0, 1> }, \
                                   { launch<K, MZ_FOR(K), 1, 0>, launch<K, MZ_FOR(K), 1, 1> } } }
struct Entry { int K, MZ; launch_fn f[2][2]; };
#ifdef ONLY_K
static const Entry TABLE[] = { ENTRY(ONLY_K) };
#else
static const Entry TABLE[] = { ENTRY(1), ENTRY(4), ENTRY(8), ENTRY(12), ENTRY(16), ENTRY(24), ENTRY(32), ENTRY(64), ENTRY(127) };
#endif

static double now() { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + 1e-9 * t.tv_nsec; }

int main(int argc, char **argv) {
    if (argc < 9) { fprintf(stderr, "usage: %s pinning.bin K sha|rmd zeros|der N seconds extra_blocks hits_out [seq]\n", argv[0]); return 1; }
    int K = atoi(argv[2]), hash = !strcmp(argv[3], "rmd"), der = !strcmp(argv[4], "der"), N = atoi(argv[5]);
    double seconds = atof(argv[6]); int extra = atoi(argv[7]); const char *hits_out = argv[8];
    uint32_t seq = argc > 9 ? (uint32_t)strtoul(argv[9], 0, 0) : 0x12345678u;
    const Entry *E = 0;
    for (auto &e : TABLE) if (e.K == K) E = &e;
    if (!E) { fprintf(stderr, "unsupported K\n"); return 1; }

    /* pinning.bin (Layr format): 8 x BE u32 midstate | u32 sufLen | suffix | u32 total | u32 seqOff | u32 ltOff | ... */
    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("bin"); return 1; }
    uint8_t raw[4096]; size_t n = fread(raw, 1, sizeof raw, f); fclose(f); (void)n;
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

    const size_t gtb = 16ULL * 65536 * 32;
    uint8_t *hX = (uint8_t *)malloc(gtb), *hY = (uint8_t *)malloc(gtb);
    compute_gtable(hX, hY);
    uint8_t *gX, *gY; CK(cudaMalloc(&gX, gtb)); CK(cudaMalloc(&gY, gtb));
    CK(cudaMemcpy(gX, hX, gtb, cudaMemcpyHostToDevice)); CK(cudaMemcpy(gY, hY, gtb, cudaMemcpyHostToDevice));
    compute_jA(K);

    const uint32_t MAXH = 1 << 20;
    uint32_t *dHC, *dH; CK(cudaMalloc(&dHC, 4)); CK(cudaMalloc(&dH, 16 * MAXH)); CK(cudaMemset(dHC, 0, 4));
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop, 0));
    dim3 block(128), grid(prop.multiProcessorCount * 8);
    uint32_t per_launch = grid.x * block.x * E->MZ;
    launch_fn fn = E->f[hash][der];

    if (getenv("POOL_DUMP")) {          /* debug: dump every (j, sign) of candidate (seq, lt=0), thread 0 */
        uint64_t *dD; CK(cudaMalloc(&dD, 8 * 6 * 2 * K));
        fn(grid, block, seq, 0, extra, gX, gY, dHC, dH, MAXH, dD); CK(cudaGetLastError()); CK(cudaDeviceSynchronize());
        uint64_t *hD = (uint64_t *)malloc(8 * 6 * 2 * K); CK(cudaMemcpy(hD, dD, 8 * 6 * 2 * K, cudaMemcpyDeviceToHost));
        for (int i = 0; i < 2 * K; i++)
            printf("DUMP %u 0 %d %d %016llx%016llx%016llx%016llx %llu %08llx\n", seq, i / 2 + 1, i % 2,
                   (unsigned long long)hD[6*i+3], (unsigned long long)hD[6*i+2], (unsigned long long)hD[6*i+1],
                   (unsigned long long)hD[6*i], (unsigned long long)hD[6*i+4], (unsigned long long)hD[6*i+5]);
        return 0;
    }
    if (getenv("POOL_STACK")) CK(cudaDeviceSetLimit(cudaLimitStackSize, atoi(getenv("POOL_STACK"))));
    fn(grid, block, seq, 0x40000000u, extra, gX, gY, dHC, dH, MAXH, nullptr);       /* warm-up, not counted */
    CK(cudaGetLastError()); CK(cudaDeviceSynchronize()); CK(cudaMemset(dHC, 0, 4));
    uint32_t lt = 0; uint64_t cand = 0; double t0 = now(), t1 = t0;
    while ((t1 = now()) - t0 < seconds) {
        for (int r = 0; r < 4; r++) {
            if ((uint64_t)lt + per_launch > 0xFFFFFFFFull) { seq++; lt = 0; }   /* never repeat a candidate */
            fn(grid, block, seq, lt, extra, gX, gY, dHC, dH, MAXH, nullptr); lt += per_launch; cand += per_launch;
        }
        CK(cudaGetLastError()); CK(cudaDeviceSynchronize());
    }
    t1 = now();
    uint32_t hc; CK(cudaMemcpy(&hc, dHC, 4, cudaMemcpyDeviceToHost));
    uint32_t keep = hc < MAXH ? hc : MAXH;
    uint32_t *hh = (uint32_t *)malloc(16 * (size_t)keep + 16);
    CK(cudaMemcpy(hh, dH, 16 * (size_t)keep, cudaMemcpyDeviceToHost));
    FILE *o = fopen(hits_out, "w");
    for (uint32_t i = 0; i < keep; i++) fprintf(o, "%u %u %u %u\n", hh[4*i], hh[4*i+1], hh[4*i+2], hh[4*i+3]);
    fclose(o);
    double el = t1 - t0, shots = (double)cand * 2 * K;
    printf("{\"gpu\":\"%s\",\"K\":%d,\"MZ\":%d,\"hash\":\"%s\",\"gate\":\"%s\",\"N\":%d,\"extra_blocks\":%d,"
           "\"seconds\":%.2f,\"candidates\":%llu,\"z_per_s\":%.4e,\"shots_per_s\":%.4e,\"hits\":%u,\"expected_hits\":%.1f}\n",
           prop.name, K, E->MZ, hash ? "rmd" : "sha", der ? "der" : "zeros", N, extra, el,
           (unsigned long long)cand, cand / el, shots / el, hc, der ? shots * 0 : shots / (double)(1ULL << N));
    return 0;
}
