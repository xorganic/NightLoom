#pragma once
#ifndef CHACHA20_H
#define CHACHA20_H

#include <Windows.h>

void ChaCha20_Crypt(PBYTE pData, DWORD cbData,
                    const BYTE key[32], const BYTE nonce[12],
                    DWORD counter);

#endif
