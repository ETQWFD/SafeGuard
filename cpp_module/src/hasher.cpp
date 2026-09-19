/*
 * hasher.cpp - SHA-256 与 MD5 标准算法实现
 * 依据 FIPS 180-4 与 RFC 1321 编写，分块读取文件，可处理大文件。
 */
#include "hasher.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>

namespace Hasher {

namespace {

/* ---------------- SHA-256 ---------------- */
struct Sha256 {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;

    Sha256() {
        h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u;
        h[2] = 0x3c6ef372u; h[3] = 0xa54ff53au;
        h[4] = 0x510e527fu; h[5] = 0x9b05688cu;
        h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
        len = 0; buflen = 0;
    }

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const unsigned char* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
                   (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const unsigned char* data, size_t n) {
        len += n;
        while (n > 0) {
            size_t take = 64 - buflen;
            if (take > n) take = n;
            std::memcpy(buf + buflen, data, take);
            buflen += take;
            data += take;
            n -= take;
            if (buflen == 64) {
                block(buf);
                buflen = 0;
            }
        }
    }

    std::string final_hex() {
        uint64_t bits = len * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        unsigned char zero = 0;
        while (buflen != 56) update(&zero, 1);
        unsigned char lenb[8];
        for (int i = 0; i < 8; ++i)
            lenb[i] = (unsigned char)(bits >> (56 - i * 8));
        update(lenb, 8);
        char out[65];
        for (int i = 0; i < 8; ++i)
            std::snprintf(out + i * 8, 9, "%08x", h[i]);
        out[64] = 0;
        return std::string(out);
    }
};

/* ---------------- MD5 ---------------- */
struct Md5 {
    uint32_t a0, b0, c0, d0;
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;

    Md5() {
        a0 = 0x67452301u; b0 = 0xefcdab89u;
        c0 = 0x98badcfeu; d0 = 0x10325476u;
        len = 0; buflen = 0;
    }

    static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
    static uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
    static uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
    static uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    static uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

    void block(const unsigned char* p) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i)
            m[i] = (uint32_t)p[i * 4] | (uint32_t)p[i * 4 + 1] << 8 |
                   (uint32_t)p[i * 4 + 2] << 16 | (uint32_t)p[i * 4 + 3] << 24;
        static const int S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21};
        static const uint32_t K[64] = {
            0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
            0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
            0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
            0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
            0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
            0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
            0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
            0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u};
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; ++i) {
            uint32_t f; int g;
            if (i < 16) { f = F(B, C, D); g = i; }
            else if (i < 32) { f = G(B, C, D); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = H(B, C, D); g = (3 * i + 5) % 16; }
            else { f = I(B, C, D); g = (7 * i) % 16; }
            uint32_t tmp = D;
            D = C; C = B;
            B = B + rol(A + f + K[i] + m[g], S[i]);
            A = tmp;
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }

    void update(const unsigned char* data, size_t n) {
        len += n;
        while (n > 0) {
            size_t take = 64 - buflen;
            if (take > n) take = n;
            std::memcpy(buf + buflen, data, take);
            buflen += take;
            data += take;
            n -= take;
            if (buflen == 64) {
                block(buf);
                buflen = 0;
            }
        }
    }

    std::string final_hex() {
        uint64_t bits = len * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        unsigned char zero = 0;
        while (buflen != 56) update(&zero, 1);
        unsigned char lenb[8];
        for (int i = 0; i < 8; ++i)
            lenb[i] = (unsigned char)(bits >> (i * 8));
        update(lenb, 8);
        char out[33];
        uint32_t v[4] = {a0, b0, c0, d0};
        for (int i = 0; i < 4; ++i) {
            uint32_t x = v[i];
            std::snprintf(out + i * 8, 9, "%02x%02x%02x%02x",
                          (x >> 0) & 0xff, (x >> 8) & 0xff,
                          (x >> 16) & 0xff, (x >> 24) & 0xff);
        }
        out[32] = 0;
        return std::string(out);
    }
};

std::string hash_file(const std::string& path, int kind) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    if (kind == 0) {
        Sha256 h;
        char buf[65536];
        while (in) {
            in.read(buf, sizeof buf);
            std::streamsize n = in.gcount();
            if (n > 0) h.update((const unsigned char*)buf, (size_t)n);
        }
        return h.final_hex();
    } else {
        Md5 h;
        char buf[65536];
        while (in) {
            in.read(buf, sizeof buf);
            std::streamsize n = in.gcount();
            if (n > 0) h.update((const unsigned char*)buf, (size_t)n);
        }
        return h.final_hex();
    }
}

std::string hash_str(const std::string& data, int kind) {
    if (kind == 0) {
        Sha256 h;
        h.update((const unsigned char*)data.data(), data.size());
        return h.final_hex();
    } else {
        Md5 h;
        h.update((const unsigned char*)data.data(), data.size());
        return h.final_hex();
    }
}

} /* anonymous namespace */

std::string file_sha256(const std::string& path) { return hash_file(path, 0); }
std::string file_md5(const std::string& path) { return hash_file(path, 1); }
std::string str_sha256(const std::string& data) { return hash_str(data, 0); }
std::string str_md5(const std::string& data) { return hash_str(data, 1); }

} /* namespace Hasher */
