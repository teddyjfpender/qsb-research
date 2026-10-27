/* Proposal-local exact FindAndDelete renderer for pool2.cu. GPLv3.
 * QSR1: midstate[8] BE, n/t/midBytes/sourceLen/outputLen LE u32,
 *       source bytes (including final padding), n drop offsets LE u32,
 *       binomial[151][8] LE u64. Every deletion is a 10-byte dummy push.
 * The output is the actual legacy SIGHASH_ALL preimage with t pushes deleted.
 */
__constant__ uint8_t cStream[11008];
__constant__ uint32_t cDrop[150];
__constant__ unsigned long long cChoose[151][8];
__constant__ int cN, cTake, cOutLen;
static unsigned long long hCombinations;

__device__ __forceinline__ void sighash_z(uint32_t seq, uint32_t lt, int extra, uint64_t z[4]) {
    (void)extra;
    unsigned long long rank = ((unsigned long long)seq << 32) | lt;
    int drops[8], selected = 0, need = cTake;
    for (int pos = 0; pos < cN && need; ++pos) {
        unsigned long long count = cChoose[cN - pos - 1][need - 1];
        if (rank < count) { drops[selected++] = cDrop[pos]; --need; }
        else rank -= count;
    }
    drops[selected] = 0x7fffffff;
    int src = 0, cut = 0;
    uint32_t state[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) state[i] = cMid[i];
    for (int block = 0; block < cOutLen; block += 64) {
        uint32_t words[16];
#pragma unroll
        for (int w = 0; w < 16; ++w) {
            uint32_t value = 0;
#pragma unroll
            for (int b = 0; b < 4; ++b) {
                if (src == drops[cut]) { src += 10; ++cut; }
                value = (value << 8) | cStream[src++];
            }
            words[w] = value;
        }
        sha256_fast(state, words);
    }
    uint32_t words[16];
#pragma unroll
    for (int i = 0; i < 8; ++i) words[i] = state[i];
    words[8] = 0x80000000;
    for (int i = 9; i < 15; ++i) words[i] = 0;
    words[15] = 256;
    uint32_t out[8]; sha256_init(out); sha256_fast(out, words);
    z[0] = ((uint64_t)out[6] << 32) | out[7];
    z[1] = ((uint64_t)out[4] << 32) | out[5];
    z[2] = ((uint64_t)out[2] << 32) | out[3];
    z[3] = ((uint64_t)out[0] << 32) | out[1];
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void load_exact(const uint8_t *raw, size_t nr, int zeros) {
    if (nr < 56 || memcmp(raw, "QSR1", 4)) { fprintf(stderr, "bad QSR1 header\n"); exit(1); }
    uint32_t mid[8];
    for (int i = 0; i < 8; ++i) {
        const uint8_t *p = raw + 4 + i * 4;
        mid[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
    int n = read_le32(raw+36), take = read_le32(raw+40), midBytes = read_le32(raw+44);
    int len = read_le32(raw+48), outLen = read_le32(raw+52);
    if (n < 7 || n > 150 || take != 7 || midBytes < 0 || midBytes % 64 ||
        len < 0 || len > 11008 || outLen != len-10*take || outLen % 64 ||
        nr != 56u + len + 4u*n + 151u*8*8) {
        fprintf(stderr, "bad QSR1 dimensions\n"); exit(1);
    }
    uint32_t drops[150] = {0};
    for (int i = 0; i < n; ++i) {
        drops[i] = read_le32(raw+56+len+4*i);
        if (drops[i]+10 > (unsigned)len || (i && drops[i] < drops[i-1]+10)) exit(1);
    }
    static unsigned long long bin[151][8];
    memcpy(bin, raw+56+len+4*n, sizeof bin); // CUDA host platform is little endian.
    hCombinations = bin[n][take];
    cudaError_t err = cudaMemcpyToSymbol(cStream, raw+56, len);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cDrop, drops, sizeof drops);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cChoose, bin, sizeof bin);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cMid, mid, sizeof mid);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cN, &n, 4);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cTake, &take, 4);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cOutLen, &outLen, 4);
    if (err == cudaSuccess) err = cudaMemcpyToSymbol(cZeros, &zeros, 4);
    if (err != cudaSuccess) { fprintf(stderr, "QSR1 CUDA: %s\n", cudaGetErrorString(err)); exit(1); }
    fprintf(stderr, "exact round n=%d t=%d midBytes=%d rehashBlocks=%d subsets=%llu\n",
            n, take, midBytes, outLen/64, hCombinations);
}
