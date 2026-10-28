#include "PebResolver.h"


#define CRC32_INIT          0xFFFFFFFF
#define CRC32_POLYNOMIAL    0xEDB88320


UINT32 Crc32bHashA(IN PCHAR pszString)
{
    UINT32  uHash   = CRC32_INIT;
    SIZE_T  idx     = 0;
    SIZE_T  len     = (SIZE_T)lstrlenA(pszString);

    while (idx != len)
    {
        uHash ^= (BYTE)pszString[idx++];

        for (INT i = 0; i < 8; i++)
            uHash = (uHash >> 1) ^ (CRC32_POLYNOMIAL & (0 - (uHash & 1)));
    }

    return ~uHash;
}


UINT32 Crc32bHashAI(IN PCHAR pszString)
{
    UINT32  uHash   = CRC32_INIT;
    SIZE_T  idx     = 0;
    SIZE_T  len     = (SIZE_T)lstrlenA(pszString);
    BYTE    bChar   = 0;

    while (idx != len)
    {
        bChar = (BYTE)pszString[idx++];

        if (bChar >= 'A' && bChar <= 'Z')
            bChar += 0x20;

        uHash ^= bChar;

        for (INT i = 0; i < 8; i++)
            uHash = (uHash >> 1) ^ (CRC32_POLYNOMIAL & (0 - (uHash & 1)));
    }

    return ~uHash;
}


UINT32 Crc32bHashW(IN PWCHAR pwszString)
{
    UINT32  uHash   = CRC32_INIT;
    SIZE_T  idx     = 0;
    SIZE_T  len     = (SIZE_T)lstrlenW(pwszString);

    while (idx != len)
    {
        uHash ^= (WCHAR)pwszString[idx++];

        for (INT i = 0; i < 8; i++)
            uHash = (uHash >> 1) ^ (CRC32_POLYNOMIAL & (0 - (uHash & 1)));
    }

    return ~uHash;
}


UINT32 Crc32bHashWI(IN PWCHAR pwszString)
{
    UINT32  uHash   = CRC32_INIT;
    SIZE_T  idx     = 0;
    SIZE_T  len     = (SIZE_T)lstrlenW(pwszString);
    WCHAR   wChar   = 0;

    while (idx != len)
    {
        wChar = (WCHAR)pwszString[idx++];

        if (wChar >= L'A' && wChar <= L'Z')
            wChar += 0x20;

        uHash ^= wChar;

        for (INT i = 0; i < 8; i++)
            uHash = (uHash >> 1) ^ (CRC32_POLYNOMIAL & (0 - (uHash & 1)));
    }

    return ~uHash;
}
