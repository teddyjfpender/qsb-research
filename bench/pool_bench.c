/* CPU microbenchmark: cost per "shot" (one hash of one recovered key) for
 *   CURRENT : per candidate z -> fixed-base u1*G (WBITS-bit windows, 256/WBITS mixed adds), two recid points
 *             u1*G +- u2*R, batched affine conversion, 2 x SHA256(33B). 2 shots per candidate.
 *   POOL    : per z -> B = (z/r)*G (same fixed-base mult), then 2k points -B +- j*A (j = 1..k) with one
 *             batched inversion shared by each +-pair, 1 x SHA256(33B) per point. 2k shots per z.
 * Both include the same sighash work per z (3 SHA-256 compressions, pinning-style midstate).
 * Uses libsecp256k1's real field/group code (vendored by the bitcoinconsensus crate), variable time.
 * This measures a CPU ratio; GPUs differ in absolute speed, but both loops are field-mul + SHA bound.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "secp256k1.c"
#include "precomputed_ecmult.c"
#include "precomputed_ecmult_gen.c"

#ifndef WBITS
#define WBITS 16
#endif
#define NWIN (256 / WBITS)
#define WSIZE (1 << WBITS)
#define BATCH 256

static secp256k1_ge *TABLE; /* TABLE[w*WSIZE + d] = d * 2^(16w) * G, d >= 1 */

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }

static void build_table(void) {
    TABLE = malloc(sizeof(secp256k1_ge) * NWIN * WSIZE);
    secp256k1_gej *tmp = malloc(sizeof(secp256k1_gej) * WSIZE);
    secp256k1_gej base; secp256k1_gej_set_ge(&base, &secp256k1_ge_const_g);
    for (int w = 0; w < NWIN; w++) {
        secp256k1_ge base_ge; secp256k1_ge_set_gej_var(&base_ge, &base);
        secp256k1_gej_set_infinity(&tmp[0]);
        for (int d = 1; d < WSIZE; d++) secp256k1_gej_add_ge_var(&tmp[d], &tmp[d - 1], &base_ge, NULL);
        secp256k1_ge_set_all_gej_var(&TABLE[w * WSIZE + 1], &tmp[1], WSIZE - 1);
        for (int i = 0; i < WBITS; i++) secp256k1_gej_double_var(&base, &base, NULL);
    }
    free(tmp);
}

/* fixed-base scalar mult with 16 windows of 16 bits; out in Jacobian */
static void fixed_base(secp256k1_gej *out, const unsigned char k32[32]) {
    secp256k1_gej_set_infinity(out);
    for (int w = 0; w < NWIN; w++) {
        int bit = w * WBITS, d = 0;
        for (int i = 0; i < WBITS; i++, bit++) d |= ((k32[31 - bit / 8] >> (bit % 8)) & 1) << i;
        if (d) secp256k1_gej_add_ge_var(out, out, &TABLE[w * WSIZE + d], NULL);
    }
}

static void sha33(const secp256k1_ge *p, unsigned char out[32]) {
    unsigned char buf[33];
    secp256k1_fe x = p->x, y = p->y;
    secp256k1_fe_normalize_var(&x); secp256k1_fe_normalize_var(&y);
    buf[0] = 2 | secp256k1_fe_is_odd(&y);
    secp256k1_fe_get_b32(buf + 1, &x);
    secp256k1_sha256 h; secp256k1_sha256_initialize(&h); secp256k1_sha256_write(&h, buf, 33); secp256k1_sha256_finalize(&h, out);
}

static secp256k1_sha256 MID;
static unsigned char TAIL[75];
static unsigned char VAR[64 * 64];
static int EXTRA_BLOCKS = 0;   /* 0: pinning shape (75-byte tail). 24: subset-round shape (~27 blocks rehashed) */
static void sighash(uint32_t ctr, unsigned char z[32]) {
    secp256k1_sha256 h = MID; unsigned char t[75]; memcpy(t, TAIL, 75); memcpy(t + 40, &ctr, 4);
    unsigned char h1[32];
    if (EXTRA_BLOCKS) { memcpy(VAR, &ctr, 4); secp256k1_sha256_write(&h, VAR, 64 * EXTRA_BLOCKS); }
    secp256k1_sha256_write(&h, t, 75); secp256k1_sha256_finalize(&h, h1);
    secp256k1_sha256_initialize(&h); secp256k1_sha256_write(&h, h1, 32); secp256k1_sha256_finalize(&h, z);
}

static volatile unsigned sink;
static long checked;

static double bench_current(long ncand) {
    secp256k1_scalar rinv_neg; secp256k1_scalar_set_int(&rinv_neg, 12345); /* stand-in for -r^-1 */
    secp256k1_gej u2R_j; secp256k1_gej_set_ge(&u2R_j, &secp256k1_ge_const_g);
    secp256k1_gej_double_var(&u2R_j, &u2R_j, NULL);
    secp256k1_ge u2R, u2Rn; secp256k1_ge_set_gej_var(&u2R, &u2R_j); secp256k1_ge_neg(&u2Rn, &u2R);
    secp256k1_gej *q = malloc(sizeof(secp256k1_gej) * 2 * BATCH);
    secp256k1_ge *qa = malloc(sizeof(secp256k1_ge) * 2 * BATCH);
    double t0 = now();
    for (long c = 0; c < ncand; c += BATCH) {
        for (int b = 0; b < BATCH; b++) {
            unsigned char z[32], u1b[32]; secp256k1_scalar zs, u1; int of;
            sighash((uint32_t)(c + b), z);
            secp256k1_scalar_set_b32(&zs, z, &of); secp256k1_scalar_mul(&u1, &zs, &rinv_neg);
            secp256k1_scalar_get_b32(u1b, &u1);
            secp256k1_gej g; fixed_base(&g, u1b);
            secp256k1_gej_add_ge_var(&q[2 * b], &g, &u2R, NULL);
            secp256k1_gej_add_ge_var(&q[2 * b + 1], &g, &u2Rn, NULL);
        }
        secp256k1_ge_set_all_gej_var(qa, q, 2 * BATCH);
        for (int i = 0; i < 2 * BATCH; i++) { unsigned char h[32]; sha33(&qa[i], h); sink ^= h[0]; }
    }
    double dt = now() - t0;
    free(q); free(qa);
    return dt / (2.0 * ncand); /* seconds per shot */
}

static double bench_pool(long nz, int k) {
    secp256k1_scalar rinv; secp256k1_scalar_set_int(&rinv, 1);                 /* r = 1 */
    secp256k1_ge *jA = malloc(sizeof(secp256k1_ge) * (k + 1));                 /* j*A, affine, constants */
    { secp256k1_gej acc, *t = malloc(sizeof(secp256k1_gej) * (k + 1)); secp256k1_gej_set_infinity(&acc);
      secp256k1_ge A; secp256k1_gej Aj; secp256k1_gej_set_ge(&Aj, &secp256k1_ge_const_g);
      secp256k1_gej_double_var(&Aj, &Aj, NULL); secp256k1_gej_double_var(&Aj, &Aj, NULL);
      secp256k1_ge_set_gej_var(&A, &Aj);
      for (int j = 1; j <= k; j++) { secp256k1_gej_add_ge_var(&acc, &acc, &A, NULL); t[j] = acc; }
      secp256k1_ge_set_all_gej_var(&jA[1], &t[1], k); free(t); }
    secp256k1_gej *Bj = malloc(sizeof(secp256k1_gej) * BATCH);
    secp256k1_ge *B = malloc(sizeof(secp256k1_ge) * BATCH);
    secp256k1_fe *dx = malloc(sizeof(secp256k1_fe) * k), *pref = malloc(sizeof(secp256k1_fe) * k);
    double t0 = now();
    for (long c = 0; c < nz; c += BATCH) {
        for (int b = 0; b < BATCH; b++) {
            unsigned char z[32], u1b[32]; secp256k1_scalar zs, u1; int of;
            sighash((uint32_t)(c + b), z);
            secp256k1_scalar_set_b32(&zs, z, &of); secp256k1_scalar_mul(&u1, &zs, &rinv);
            secp256k1_scalar_get_b32(u1b, &u1);
            fixed_base(&Bj[b], u1b);
        }
        secp256k1_ge_set_all_gej_var(B, Bj, BATCH);
        for (int b = 0; b < BATCH; b++) {
            secp256k1_fe xB = B[b].x, yN; secp256k1_fe_normalize_var(&xB);
            yN = B[b].y; secp256k1_fe_normalize_var(&yN); secp256k1_fe_negate(&yN, &yN, 1); /* -B */
            secp256k1_fe_normalize_var(&yN);
            /* Montgomery batch inversion of dx_j = x_jA - x_B */
            secp256k1_fe acc; secp256k1_fe_set_int(&acc, 1);
            for (int j = 0; j < k; j++) {
                secp256k1_fe nx; secp256k1_fe_negate(&nx, &xB, 1);
                dx[j] = jA[j + 1].x; secp256k1_fe_add(&dx[j], &nx);
                pref[j] = acc; secp256k1_fe_mul(&acc, &acc, &dx[j]);
            }
            secp256k1_fe_inv_var(&acc, &acc);
            for (int j = k - 1; j >= 0; j--) {
                secp256k1_fe inv_j; secp256k1_fe_mul(&inv_j, &acc, &pref[j]); secp256k1_fe_mul(&acc, &acc, &dx[j]);
                const secp256k1_ge *P = &jA[j + 1];
                for (int sgn = 0; sgn < 2; sgn++) {                      /* -B + jA, -B - jA */
                    secp256k1_fe yP = P->y, lam, x3, y3, t;
                    if (sgn) { secp256k1_fe_negate(&yP, &yP, 1); }
                    secp256k1_fe_negate(&t, &yN, 1); lam = yP; secp256k1_fe_add(&lam, &t);   /* yP - yN */
                    secp256k1_fe_mul(&lam, &lam, &inv_j);
                    secp256k1_fe_sqr(&x3, &lam);
                    secp256k1_fe_negate(&t, &xB, 1); secp256k1_fe_add(&x3, &t);
                    secp256k1_fe_negate(&t, &P->x, 1); secp256k1_fe_add(&x3, &t);
                    secp256k1_fe_normalize_var(&x3);
                    secp256k1_fe_negate(&t, &x3, 1); y3 = xB; secp256k1_fe_add(&y3, &t);        /* xB - x3 */
                    secp256k1_fe_mul(&y3, &y3, &lam);
                    secp256k1_fe_negate(&t, &yN, 1); secp256k1_fe_add(&y3, &t);
                    secp256k1_ge pt; pt.x = x3; pt.y = y3; pt.infinity = 0;
                    if (c == 0 && b == 0) {                                   /* self-check, first z only */
                        secp256k1_gej ref; secp256k1_ge Bneg, jr; secp256k1_ge_neg(&Bneg, &B[b]);
                        secp256k1_gej_set_ge(&ref, &Bneg);
                        jr = *P; if (sgn) secp256k1_ge_neg(&jr, P);
                        secp256k1_gej_add_ge_var(&ref, &ref, &jr, NULL);
                        secp256k1_ge refa; secp256k1_ge_set_gej_var(&refa, &ref);
                        secp256k1_fe a1 = refa.x, a2 = refa.y, b1 = x3, b2 = y3;
                        secp256k1_fe_normalize_var(&a1); secp256k1_fe_normalize_var(&a2);
                        secp256k1_fe_normalize_var(&b1); secp256k1_fe_normalize_var(&b2);
                        if (!secp256k1_fe_equal(&a1, &b1) || !secp256k1_fe_equal(&a2, &b2)) { fprintf(stderr, "POOL POINT MISMATCH j=%d sgn=%d\n", j + 1, sgn); exit(1); }
                        checked++;
                    }
                    unsigned char h[32]; sha33(&pt, h); sink ^= h[0];
                }
            }
        }
    }
    double dt = now() - t0;
    free(jA); free(Bj); free(B); free(dx); free(pref);
    return dt / (2.0 * k * nz);
}

static double bench_hash_only(long n) {
    secp256k1_ge p = secp256k1_ge_const_g; double t0 = now();
    for (long i = 0; i < n; i++) { unsigned char h[32]; p.x.n[0] ^= i; sha33(&p, h); sink ^= h[0]; }
    return (now() - t0) / n;
}

int main(int argc, char **argv) {
    long ncand = argc > 1 ? atol(argv[1]) : 1L << 17;
    EXTRA_BLOCKS = argc > 2 ? atoi(argv[2]) : 0;
    printf("sighash shape: %d SHA-256 compressions per z\n", 3 + EXTRA_BLOCKS);
    secp256k1_sha256_initialize(&MID);
    unsigned char blk[64] = {0}; for (int i = 0; i < 155; i++) secp256k1_sha256_write(&MID, blk, 64);
    for (int i = 0; i < 75; i++) TAIL[i] = (unsigned char)(i * 7);
    double tb = now(); build_table(); fprintf(stderr, "table built in %.1fs\n", now() - tb);

    double hash = bench_hash_only(ncand * 4);
    double cur = bench_current(ncand);
    printf("SHA256(33B) alone          : %7.1f ns\n", hash * 1e9);
    printf("CURRENT  per shot          : %7.1f ns   (per candidate %.1f ns, 2 shots)\n", cur * 1e9, 2 * cur * 1e9);
    int ks[] = {4, 8, 12, 16, 24, 32, 64, 127};
    for (unsigned i = 0; i < sizeof ks / sizeof *ks; i++) {
        long nz = (ncand * 2) / (2 * ks[i]); if (nz < BATCH) nz = BATCH; nz = (nz / BATCH) * BATCH;
        double p = bench_pool(nz, ks[i]);
        printf("POOL k=%-3d per shot        : %7.1f ns   speedup x%.2f   (hash share %.0f%%)\n",
               ks[i], p * 1e9, cur / p, 100 * hash / p);
    }
    fprintf(stderr, "pool points cross-checked against libsecp256k1 group addition: %ld\n", checked);
    return (int)(sink & 0);
}
