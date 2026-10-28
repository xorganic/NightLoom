#include "ChaCha20.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static void ChaCha20_Block(DWORD out[16], const DWORD in[16])
{
    DWORD x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];

    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static DWORD LoadLE32(const BYTE *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

void ChaCha20_Crypt(PBYTE pData, DWORD cbData,
                    const BYTE key[32], const BYTE nonce[12],
                    DWORD counter)
{
    DWORD state[16];

    state[ 0] = 0x61707865;
    state[ 1] = 0x3320646e;
    state[ 2] = 0x79622d32;
    state[ 3] = 0x6b206574;

    for (int i = 0; i < 8; i++)
        state[4 + i] = LoadLE32(key + i * 4);

    state[12] = counter;

    for (int i = 0; i < 3; i++)
        state[13 + i] = LoadLE32(nonce + i * 4);

    DWORD offset = 0;
    while (offset < cbData) {
        DWORD keystream[16];
        ChaCha20_Block(keystream, state);

        DWORD blockLen = cbData - offset;
        if (blockLen > 64) blockLen = 64;

        PBYTE ks = (PBYTE)keystream;
        for (DWORD j = 0; j < blockLen; j++)
            pData[offset + j] ^= ks[j];

        state[12]++;
        offset += 64;
    }
}
