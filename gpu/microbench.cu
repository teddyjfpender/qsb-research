/* microbench.cu -- throughput of the primitives used by pool2 on the current GPU.
 * Each thread runs a dependent chain; results are folded into a sink so nothing is optimized away.
 * Build: nvcc -O3 -arch=sm_89 -o microbench microbench.cu
 */
#include <stdio.h>
#include <stdint.h>
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
#define POOL2_FIELD_ONLY
#include "field2.cuh"

__global__ void k_fmul(uint64_t *sink, int iters) {
    uint64_t a[4] = {threadIdx.x + 1ull, blockIdx.x + 7ull, 0x1234567ull, 0x89abcdefull}, b[4] = {3, 5, 7, 11};
    for (int i = 0; i < iters; i++) { fmul(a, a, b); b[0] ^= a[3]; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = a[0] ^ a[1] ^ a[2] ^ a[3];
}
__global__ void k_fsqr(uint64_t *sink, int iters) {
    uint64_t a[4] = {threadIdx.x + 1ull, blockIdx.x + 7ull, 0x1234567ull, 0x89abcdefull};
    for (int i = 0; i < iters; i++) { fsqr(a, a); a[0] ^= i; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = a[0] ^ a[1] ^ a[2] ^ a[3];
}
__global__ void k_vsmul(uint64_t *sink, int iters) {        /* VanitySearch _ModMult for comparison */
    uint64_t a[5] = {threadIdx.x + 1ull, blockIdx.x + 7ull, 0x1234567ull, 0x89abcdefull, 0}, b[4] = {3, 5, 7, 11};
    for (int i = 0; i < iters; i++) { _ModMult(a, a, b); b[0] ^= a[3]; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = a[0] ^ a[1] ^ a[2] ^ a[3];
}
__global__ void k_sha(uint64_t *sink, int iters) {
    uint32_t s[8]; sha256_init(s); uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = 0; w[0] = threadIdx.x; w[8] = 0x800000; w[15] = 264;
    for (int i = 0; i < iters; i++) { uint32_t t[8]; sha256_init(t); w[1] = s[0] ^ i; sha256_fast(t, w); s[0] ^= t[0]; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = s[0];
}
__global__ void k_sha_old(uint64_t *sink, int iters) {
    uint32_t s[8]; _SHA256Initialize(s); uint32_t w[16];
    for (int i = 0; i < iters; i++) {
        for (int j = 0; j < 16; j++) w[j] = 0; w[0] = threadIdx.x; w[8] = 0x800000; w[15] = 264;
        uint32_t t[8]; _SHA256Initialize(t); w[1] = s[0] ^ i; _SHA256Transform(t, w); s[0] ^= t[0];
    }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = s[0];
}
__global__ void k_rmd(uint64_t *sink, int iters) {
    uint32_t s0 = 0; uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = 0; w[0] = threadIdx.x; w[8] = 0x8000; w[14] = 264;
    for (int i = 0; i < iters; i++) { uint32_t t[5]; ripemd160_init(t); w[1] = s0 ^ i; ripemd160_fast(t, w); s0 ^= t[0]; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = s0;
}
__global__ void k_inv(uint64_t *sink, int iters) {
    uint64_t a[4] = {threadIdx.x + 12345ull, blockIdx.x + 7ull, 0x1234567ull, 0x89abcdefull};
    for (int i = 0; i < iters; i++) { finv(a, a); a[0] += 1; }
    sink[blockIdx.x * blockDim.x + threadIdx.x] = a[0];
}

typedef void (*kfn)(uint64_t *, int);
int main() {
    cudaDeviceProp p; cudaGetDeviceProperties(&p, 0);
    int blocks = p.multiProcessorCount * 8, tpb = 128; uint64_t *sink; cudaMalloc(&sink, 8ull * blocks * tpb);
    struct { const char *name; kfn f; int iters; } T[] = {
        {"fmul (u128 limbs)", k_fmul, 4096}, {"fsqr", k_fsqr, 4096}, {"VanitySearch _ModMult", k_vsmul, 4096},
        {"SHA-256 compress (fast)", k_sha, 1024}, {"SHA-256 compress (GPUHash)", k_sha_old, 1024},
        {"RIPEMD-160 compress (fast)", k_rmd, 1024}, {"ModInv (_ModInv)", k_inv, 64}};
    cudaEvent_t e0, e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    for (auto &t : T) {
        t.f<<<blocks, tpb>>>(sink, 16); cudaDeviceSynchronize();
        cudaEventRecord(e0); t.f<<<blocks, tpb>>>(sink, t.iters); cudaEventRecord(e1); cudaEventSynchronize(e1);
        float ms; cudaEventElapsedTime(&ms, e0, e1);
        double ops = (double)blocks * tpb * t.iters;
        printf("%-28s %8.2f G ops/s   %7.4f ns/op (whole GPU)\n", t.name, ops / ms / 1e6, ms * 1e6 / ops);
    }
    printf("err: %s\n", cudaGetErrorString(cudaGetLastError()));
    return 0;
}
