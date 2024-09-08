#ifndef XXHASH_BPF_H
#define XXHASH_BPF_H

#define PRIME1 0x9E3779B1U
#define PRIME2 0x85EBCA77U
#define PRIME3 0xC2B2AE3DU
#define PRIME4 0x27D4EB2FU
#define PRIME5 0x165667B1U

static __always_inline unsigned int rotl (unsigned int x, int r) {
    return ((x << r) | (x >> (32 - r)));
}
// Normal stripe processing routine.
static __always_inline unsigned int round_xxhash(unsigned int acc, const unsigned int input) {
    return rotl(acc + (input * PRIME2), 13) * PRIME1;
}

static __always_inline unsigned int avalanche_step (const unsigned int h, const int rshift, const unsigned int prime) {
    return (h ^ (h >> rshift)) * prime;
}
// Mixes all bits to finalize the hash.
static __always_inline unsigned int avalanche (const unsigned int h) {
    return avalanche_step(avalanche_step(avalanche_step(h, 15, PRIME2), 13, PRIME3), 16, 1);
}

static __always_inline unsigned int endian32 (const char *v) {
    return (unsigned int)((unsigned char)(v[0]))|((unsigned int)((unsigned char)(v[1])) << 8)
            |((unsigned int)((unsigned char)(v[2])) << 16)|((unsigned int)((unsigned char)(v[3])) << 24);
}

static __always_inline unsigned int fetch32 (const char *p, const unsigned int v) {
    return round_xxhash(v, endian32(p));
}

// Processes the last 0-15 bytes of p.
static __always_inline unsigned int finalize (const unsigned int h, const char *p, unsigned int len) {
    return
        (len >= 4) ? finalize(rotl(h + (endian32(p) * PRIME3), 17) * PRIME4, p + 4, len - 4) :
        (len > 0)  ? finalize(rotl(h + ((unsigned char)(*p) * PRIME5), 11) * PRIME1, p + 1, len - 1) :
        avalanche(h);
}

static __always_inline unsigned int h16bytes_4 (const char *p, unsigned int len, const unsigned int v1, const unsigned int v2, const unsigned int v3, const unsigned int v4) {
    return
        (len >= 16) ? h16bytes_4(p + 16, len - 16, fetch32(p, v1), fetch32(p+4, v2), fetch32(p+8, v3), fetch32(p+12, v4)) :
        rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
}

static __always_inline unsigned int h16bytes_3 (const char *p, unsigned int len, const unsigned int seed) {
    return h16bytes_4(p, len, seed + PRIME1 + PRIME2, seed + PRIME2, seed, seed - PRIME1);
}

static __always_inline unsigned int xxhash32 (const char *input, unsigned int len, unsigned int seed) {
    return finalize((len >= 16 ? h16bytes_3(input, len, seed) : seed + PRIME5) + len, (input) + (len & ~0xF), len & 0xF);
}

#endif
