#include "PebResolver.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region API_SET_RESOLUTION

static PAPI_SET_NAMESPACE_ENTRY_V6 SearchApiSetV6(IN PAPI_SET_NAMESPACE_V6 pMap, IN PWSTR pwszName, IN USHORT usLen)
{
    PWCHAR                      pwc             = NULL;
    DWORD                       dwKey           = 0;
    DWORD                       dwFactor        = 0;
    DWORD                       dwHashOff       = 0;
    DWORD                       dwEntryOff      = 0;
    DWORD                       dwCount         = 0;
    DWORD                       dwHashedLen     = 0;
    DWORD                       dwL             = 0;
    DWORD                       dwR             = 0;
    DWORD                       dwM             = 0;
    PAPI_SET_HASH_ENTRY_V6      pH              = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V6 pFound          = NULL;
    PWCHAR                      pwszEntry       = NULL;

    if (!pMap || !pwszName || !usLen) return NULL;

    dwFactor    = MEM_RD(pMap, API_SET_NAMESPACE_V6, HashFactor);
    dwHashOff   = MEM_RD(pMap, API_SET_NAMESPACE_V6, HashOffset);
    dwEntryOff  = MEM_RD(pMap, API_SET_NAMESPACE_V6, EntryOffset);
    dwCount     = MEM_RD(pMap, API_SET_NAMESPACE_V6, Count);

    if (!dwCount) return NULL;

    pwc = pwszName;
    for (USHORT n = usLen; n; n--, pwc++)
        dwKey = dwKey * dwFactor + (USHORT)CHAR_TO_LOWER_W(*pwc);

    dwL = 0;
    dwR = dwCount - 1;

    while (dwL <= dwR)
    {
        dwM = dwL + (dwR - dwL) / 2;
        pH = (PAPI_SET_HASH_ENTRY_V6)((PBYTE)pMap + dwHashOff + (dwM * sizeof(API_SET_HASH_ENTRY_V6)));

        DWORD dwH = MEM_RD(pH, API_SET_HASH_ENTRY_V6, Hash);

        if (dwKey < dwH)        { if (dwM == 0) break; dwR = dwM - 1; }
        else if (dwKey > dwH)   { dwL = dwM + 1; }
        else
        {
            DWORD idx = MEM_RD(pH, API_SET_HASH_ENTRY_V6, Index);
            pFound = (PAPI_SET_NAMESPACE_ENTRY_V6)((PBYTE)pMap + dwEntryOff + (idx * sizeof(API_SET_NAMESPACE_ENTRY_V6)));
            break;
        }
    }

    if (!pFound) return NULL;

    pwszEntry   = (PWCHAR)((PBYTE)pMap + MEM_RD(pFound, API_SET_NAMESPACE_ENTRY_V6, NameOffset));
    dwHashedLen = MEM_RD(pFound, API_SET_NAMESPACE_ENTRY_V6, HashedLength) / sizeof(WCHAR);

    for (DWORD i = 0; i < dwHashedLen; i++)
    {
        WCHAR wc1 = CHAR_TO_LOWER_W(pwszName[i]);
        WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszEntry[i]);
        WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
        if (wc1 != wc2) return NULL;
    }

    return pFound;
}

static PAPI_SET_VALUE_ENTRY_V6 SearchApiSetHostV6(IN PAPI_SET_NAMESPACE_V6 pMap, IN PAPI_SET_NAMESPACE_ENTRY_V6 pEnt, IN PWSTR pwszParent, IN USHORT usParentLen)
{
    DWORD                   dwL         = 0;
    DWORD                   dwR         = 0;
    DWORD                   dwM         = 0;
    DWORD                   dwValOff    = 0;
    DWORD                   dwValCnt    = 0;
    PAPI_SET_VALUE_ENTRY_V6 pVal        = NULL;
    PAPI_SET_VALUE_ENTRY_V6 pHost       = NULL;

    if (!pEnt || !pMap) return NULL;

    dwValOff = MEM_RD(pEnt, API_SET_NAMESPACE_ENTRY_V6, ValueOffset);
    dwValCnt = MEM_RD(pEnt, API_SET_NAMESPACE_ENTRY_V6, ValueCount);

    pVal = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pMap + dwValOff);

    if (dwValCnt <= 1 || !pwszParent || !usParentLen)
        return pVal;

    dwL = 1;
    dwR = dwValCnt - 1;

    while (dwL <= dwR)
    {
        dwM = dwL + (dwR - dwL) / 2;
        pHost = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pMap + dwValOff + (dwM * sizeof(API_SET_VALUE_ENTRY_V6)));

        PWCHAR  pwszH   = (PWCHAR)((PBYTE)pMap + MEM_RD(pHost, API_SET_VALUE_ENTRY_V6, NameOffset));
        DWORD   dwHLen  = MEM_RD(pHost, API_SET_VALUE_ENTRY_V6, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usParentLen, dwHLen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParent[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszH[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }

        if (lCmp == 0 && usParentLen != dwHLen)
            lCmp = (usParentLen < dwHLen) ? -1 : 1;

        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { return pHost; }
    }

    return pVal;
}

static BOOL ResolveApiSetV6(IN PAPI_SET_NAMESPACE_V6 pMap, IN PCWSTR pwszName, IN OPTIONAL PCWSTR pwszParent, OUT PWSTR pwszOut, IN DWORD dwMax)
{
    DWORD   dwLen       = 0;
    USHORT  usNoExt     = 0;
    PWCHAR  pwc         = NULL;

    if (!pMap || !pwszName || !pwszOut || !dwMax) return FALSE;

    for (dwLen = 0; pwszName[dwLen]; dwLen++);
    if (dwLen < 4) return FALSE;

    ULONGLONG ullPfx = *(ULONGLONG*)pwszName;
    ullPfx &= ~(ULONGLONG)0x0000002000200020;
    if (ullPfx != API_SET_PREFIX_API && ullPfx != API_SET_PREFIX_EXT) return FALSE;

    pwc = (PWCHAR)pwszName + dwLen;
    usNoExt = (USHORT)dwLen;
    while (usNoExt > 0) { pwc--; usNoExt--; if (*pwc == L'-') break; }
    if (!usNoExt) return FALSE;

    PAPI_SET_NAMESPACE_ENTRY_V6 pNs = SearchApiSetV6(pMap, (PWSTR)pwszName, usNoExt);
    if (!pNs) return FALSE;

    DWORD dwParLen = 0;
    if (pwszParent) for (dwParLen = 0; pwszParent[dwParLen]; dwParLen++);

    DWORD dwValCnt = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V6, ValueCount);
    DWORD dwValOff = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V6, ValueOffset);

    PAPI_SET_VALUE_ENTRY_V6 pVal = NULL;
    if (dwValCnt > 1 && pwszParent && dwParLen)
        pVal = SearchApiSetHostV6(pMap, pNs, (PWSTR)pwszParent, (USHORT)dwParLen);
    else if (dwValCnt > 0)
        pVal = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pMap + dwValOff);
    else
        return FALSE;

    if (!pVal) return FALSE;

    PWCHAR pwszRes = (PWCHAR)((PBYTE)pMap + MEM_RD(pVal, API_SET_VALUE_ENTRY_V6, ValueOffset));
    DWORD  dwResLen = MEM_RD(pVal, API_SET_VALUE_ENTRY_V6, ValueLength) / sizeof(WCHAR);
    if (dwResLen >= dwMax) return FALSE;

    for (DWORD i = 0; i < dwResLen; i++)
        pwszOut[i] = (WCHAR)MEM_RW_RAW(&pwszRes[i]);
    pwszOut[dwResLen] = L'\0';

    return TRUE;
}

static PAPI_SET_NAMESPACE_ENTRY_V4 SearchApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pArr, IN PWSTR pwszName, IN USHORT usLen)
{
    DWORD dwCount = MEM_RD(pArr, API_SET_NAMESPACE_ARRAY_V4, Count);
    if (!pArr || !pwszName || !usLen || !dwCount) return NULL;

    DWORD dwL = 0, dwR = dwCount - 1;

    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        PAPI_SET_NAMESPACE_ENTRY_V4 pE = (PAPI_SET_NAMESPACE_ENTRY_V4)((PBYTE)pArr + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V4, Array) + (dwM * sizeof(API_SET_NAMESPACE_ENTRY_V4)));
        PWCHAR  pwszE   = (PWCHAR)((PBYTE)pArr + MEM_RD(pE, API_SET_NAMESPACE_ENTRY_V4, NameOffset));
        DWORD   dwELen  = MEM_RD(pE, API_SET_NAMESPACE_ENTRY_V4, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usLen, dwELen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszName[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszE[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }

        if (lCmp == 0 && usLen != dwELen) lCmp = (usLen < dwELen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { return pE; }
    }
    return NULL;
}

static PAPI_SET_VALUE_ENTRY_V4 SearchApiSetHostV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pArr, IN PAPI_SET_VALUE_ARRAY_V4 pVA, IN PWSTR pwszParent, IN USHORT usParLen)
{
    if (!pVA || !pArr) return NULL;
    DWORD dwCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V4, Count);
    if (dwCnt <= 1 || !pwszParent || !usParLen) return NULL;

    DWORD dwL = 1, dwR = dwCnt - 1;
    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        PAPI_SET_VALUE_ENTRY_V4 pH = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array) + (dwM * sizeof(API_SET_VALUE_ENTRY_V4)));
        PWCHAR  pwszH   = (PWCHAR)((PBYTE)pArr + MEM_RD(pH, API_SET_VALUE_ENTRY_V4, NameOffset));
        DWORD   dwHLen  = MEM_RD(pH, API_SET_VALUE_ENTRY_V4, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usParLen, dwHLen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParent[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszH[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }
        if (lCmp == 0 && usParLen != dwHLen) lCmp = (usParLen < dwHLen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { return pH; }
    }
    return NULL;
}

static BOOL ResolveApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pArr, IN PCWSTR pwszName, IN OPTIONAL PCWSTR pwszParent, OUT PWSTR pwszOut, IN DWORD dwMax)
{
    if (!pArr || !pwszName || !pwszOut || !dwMax) return FALSE;
    DWORD dwLen = 0;
    for (dwLen = 0; pwszName[dwLen]; dwLen++);
    if (dwLen < 8) return FALSE;

    ULONGLONG ullPfx = *(ULONGLONG*)pwszName;
    ullPfx &= ~(ULONGLONG)0x0000002000200020;
    if (ullPfx != API_SET_PREFIX_API && ullPfx != API_SET_PREFIX_EXT) return FALSE;

    PWSTR   pwszNP  = (PWSTR)(pwszName + 4);
    USHORT  usNE    = (USHORT)(dwLen - 4);

    if (usNE >= 4 && pwszNP[usNE-4] == L'.' && CHAR_TO_LOWER_W(pwszNP[usNE-3]) == L'd' && CHAR_TO_LOWER_W(pwszNP[usNE-2]) == L'l' && CHAR_TO_LOWER_W(pwszNP[usNE-1]) == L'l')
        usNE -= 4;
    if (!usNE) return FALSE;

    PAPI_SET_NAMESPACE_ENTRY_V4 pNs = SearchApiSetV4(pArr, pwszNP, usNE);
    if (!pNs) return FALSE;

    DWORD dwDataOff = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V4, DataOffset);
    PAPI_SET_VALUE_ARRAY_V4 pVA = (PAPI_SET_VALUE_ARRAY_V4)((PBYTE)pArr + dwDataOff);
    if (!pVA) return FALSE;

    DWORD dwVCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V4, Count);
    if (!dwVCnt) return FALSE;

    DWORD dwParLen = 0;
    if (pwszParent) for (dwParLen = 0; pwszParent[dwParLen]; dwParLen++);

    PAPI_SET_VALUE_ENTRY_V4 pVal = NULL;
    if (dwVCnt > 1 && pwszParent && dwParLen)
    {
        pVal = SearchApiSetHostV4(pArr, pVA, (PWSTR)pwszParent, (USHORT)dwParLen);
        if (!pVal) pVal = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array));
    }
    else
        pVal = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array));

    if (!pVal) return FALSE;

    PWCHAR pwszRes = (PWCHAR)((PBYTE)pArr + MEM_RD(pVal, API_SET_VALUE_ENTRY_V4, ValueOffset));
    DWORD  dwResLen = MEM_RD(pVal, API_SET_VALUE_ENTRY_V4, ValueLength) / sizeof(WCHAR);
    if (dwResLen >= dwMax) return FALSE;

    for (DWORD i = 0; i < dwResLen; i++) pwszOut[i] = (WCHAR)MEM_RW_RAW(&pwszRes[i]);
    pwszOut[dwResLen] = L'\0';
    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V3 SearchApiSetHostV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pArr, IN PAPI_SET_VALUE_ARRAY_V3 pVA, IN PWSTR pwszParent, IN USHORT usParLen)
{
    if (!pVA || !pArr) return NULL;
    DWORD dwCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V3, Count);
    if (dwCnt <= 1 || !pwszParent || !usParLen) return NULL;

    DWORD dwL = 1, dwR = dwCnt - 1;
    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        PAPI_SET_VALUE_ENTRY_V3 pV = (PAPI_SET_VALUE_ENTRY_V3)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V3, Array) + (dwM * sizeof(API_SET_VALUE_ENTRY_V3)));
        PWCHAR  pwszH   = (PWCHAR)((PBYTE)pArr + MEM_RD(pV, API_SET_VALUE_ENTRY_V3, NameOffset));
        DWORD   dwHLen  = MEM_RD(pV, API_SET_VALUE_ENTRY_V3, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usParLen, dwHLen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParent[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszH[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }
        if (lCmp == 0 && usParLen != dwHLen) lCmp = (usParLen < dwHLen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { return pV; }
    }
    return NULL;
}

static BOOL ResolveApiSetV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pArr, IN PCWSTR pwszName, IN OPTIONAL PCWSTR pwszParent, OUT PWSTR pwszOut, IN DWORD dwMax)
{
    if (!pArr || !pwszName || !pwszOut || !dwMax) return FALSE;
    DWORD dwLen = 0;
    for (dwLen = 0; pwszName[dwLen]; dwLen++);
    if (dwLen < 8) return FALSE;

    ULONGLONG ullPfx = *(ULONGLONG*)pwszName;
    ullPfx &= ~(ULONGLONG)0x0000002000200020;
    if (ullPfx != API_SET_PREFIX_API && ullPfx != API_SET_PREFIX_EXT) return FALSE;

    PWSTR   pwszNP  = (PWSTR)(pwszName + 4);
    USHORT  usNE    = (USHORT)(dwLen - 4);

    if (usNE >= 4 && pwszNP[usNE-4] == L'.' && CHAR_TO_LOWER_W(pwszNP[usNE-3]) == L'd' && CHAR_TO_LOWER_W(pwszNP[usNE-2]) == L'l' && CHAR_TO_LOWER_W(pwszNP[usNE-1]) == L'l')
        usNE -= 4;
    if (!usNE) return FALSE;

    DWORD dwArrCnt = MEM_RD(pArr, API_SET_NAMESPACE_ARRAY_V3, Count);
    if (!dwArrCnt) return FALSE;

    DWORD dwL = 0, dwR = dwArrCnt - 1;
    BOOL bFound = FALSE;
    PAPI_SET_NAMESPACE_ENTRY_V3 pNs = NULL;

    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        pNs = (PAPI_SET_NAMESPACE_ENTRY_V3)((PBYTE)pArr + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V3, Array) + (dwM * sizeof(API_SET_NAMESPACE_ENTRY_V3)));
        PWCHAR  pwszE   = (PWCHAR)((PBYTE)pArr + MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V3, NameOffset));
        DWORD   dwELen  = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V3, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usNE, dwELen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNP[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszE[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }
        if (lCmp == 0 && usNE != dwELen) lCmp = (usNE < dwELen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { bFound = TRUE; break; }
    }

    if (!bFound || !pNs) return FALSE;

    DWORD dwDataOff = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V3, DataOffset);
    PAPI_SET_VALUE_ARRAY_V3 pVA = (PAPI_SET_VALUE_ARRAY_V3)((PBYTE)pArr + dwDataOff);
    if (!pVA) return FALSE;

    DWORD dwVCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V3, Count);
    if (!dwVCnt) return FALSE;

    DWORD dwParLen = 0;
    if (pwszParent) for (dwParLen = 0; pwszParent[dwParLen]; dwParLen++);

    PAPI_SET_VALUE_ENTRY_V3 pVal = NULL;
    if (dwVCnt > 1 && pwszParent && dwParLen)
        pVal = SearchApiSetHostV3(pArr, pVA, (PWSTR)pwszParent, (USHORT)dwParLen);
    if (!pVal)
        pVal = (PAPI_SET_VALUE_ENTRY_V3)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V3, Array));
    if (!pVal) return FALSE;

    PWCHAR pwszRes = (PWCHAR)((PBYTE)pArr + MEM_RD(pVal, API_SET_VALUE_ENTRY_V3, ValueOffset));
    DWORD  dwResLen = MEM_RD(pVal, API_SET_VALUE_ENTRY_V3, ValueLength) / sizeof(WCHAR);
    if (dwResLen >= dwMax) return FALSE;

    for (DWORD i = 0; i < dwResLen; i++) pwszOut[i] = (WCHAR)MEM_RW_RAW(&pwszRes[i]);
    pwszOut[dwResLen] = L'\0';
    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V2 SearchApiSetHostV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pArr, IN PAPI_SET_VALUE_ARRAY_V2 pVA, IN PWSTR pwszParent, IN USHORT usParLen)
{
    if (!pVA || !pArr) return NULL;
    DWORD dwCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V2, Count);
    if (dwCnt <= 1 || !pwszParent || !usParLen) return NULL;

    DWORD dwL = 1, dwR = dwCnt - 1;
    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        PAPI_SET_VALUE_ENTRY_V2 pV = (PAPI_SET_VALUE_ENTRY_V2)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V2, Array) + (dwM * sizeof(API_SET_VALUE_ENTRY_V2)));
        PWCHAR  pwszH   = (PWCHAR)((PBYTE)pArr + MEM_RD(pV, API_SET_VALUE_ENTRY_V2, NameOffset));
        DWORD   dwHLen  = MEM_RD(pV, API_SET_VALUE_ENTRY_V2, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usParLen, dwHLen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParent[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszH[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }
        if (lCmp == 0 && usParLen != dwHLen) lCmp = (usParLen < dwHLen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { return pV; }
    }
    return NULL;
}

static BOOL ResolveApiSetV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pArr, IN PCWSTR pwszName, IN OPTIONAL PCWSTR pwszParent, OUT PWSTR pwszOut, IN DWORD dwMax)
{
    if (!pArr || !pwszName || !pwszOut || !dwMax) return FALSE;
    DWORD dwLen = 0;
    for (dwLen = 0; pwszName[dwLen]; dwLen++);
    if (dwLen < 8) return FALSE;

    ULONGLONG ullPfx = *(ULONGLONG*)pwszName;
    ullPfx &= ~(ULONGLONG)0x0000002000200020;
    if (ullPfx != API_SET_PREFIX_API) return FALSE;

    PWSTR   pwszNP  = (PWSTR)(pwszName + 4);
    USHORT  usNE    = (USHORT)(dwLen - 4);

    if (usNE >= 4 && pwszNP[usNE-4] == L'.' && CHAR_TO_LOWER_W(pwszNP[usNE-3]) == L'd' && CHAR_TO_LOWER_W(pwszNP[usNE-2]) == L'l' && CHAR_TO_LOWER_W(pwszNP[usNE-1]) == L'l')
        usNE -= 4;
    if (!usNE) return FALSE;

    DWORD dwArrCnt = MEM_RD(pArr, API_SET_NAMESPACE_ARRAY_V2, Count);
    if (!dwArrCnt) return FALSE;

    DWORD dwL = 0, dwR = dwArrCnt - 1;
    BOOL bFound = FALSE;
    PAPI_SET_NAMESPACE_ENTRY_V2 pNs = NULL;

    while (dwL <= dwR)
    {
        DWORD dwM = dwL + (dwR - dwL) / 2;
        pNs = (PAPI_SET_NAMESPACE_ENTRY_V2)((PBYTE)pArr + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V2, Array) + (dwM * sizeof(API_SET_NAMESPACE_ENTRY_V2)));
        PWCHAR  pwszE   = (PWCHAR)((PBYTE)pArr + MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V2, NameOffset));
        DWORD   dwELen  = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V2, NameLength) / sizeof(WCHAR);
        DWORD   dwCmp   = min(usNE, dwELen);
        LONG    lCmp    = 0;

        for (DWORD i = 0; i < dwCmp; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNP[i]);
            WCHAR wcR = (WCHAR)MEM_RW_RAW(&pwszE[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(wcR);
            if (wc1 < wc2) { lCmp = -1; break; }
            else if (wc1 > wc2) { lCmp = 1; break; }
        }
        if (lCmp == 0 && usNE != dwELen) lCmp = (usNE < dwELen) ? -1 : 1;
        if (lCmp < 0)       { if (dwM == 0) break; dwR = dwM - 1; }
        else if (lCmp > 0)  { dwL = dwM + 1; }
        else                { bFound = TRUE; break; }
    }

    if (!bFound || !pNs) return FALSE;

    DWORD dwDataOff = MEM_RD(pNs, API_SET_NAMESPACE_ENTRY_V2, DataOffset);
    PAPI_SET_VALUE_ARRAY_V2 pVA = (PAPI_SET_VALUE_ARRAY_V2)((PBYTE)pArr + dwDataOff);
    if (!pVA) return FALSE;

    DWORD dwVCnt = MEM_RD(pVA, API_SET_VALUE_ARRAY_V2, Count);
    if (!dwVCnt) return FALSE;

    DWORD dwParLen = 0;
    if (pwszParent) for (dwParLen = 0; pwszParent[dwParLen]; dwParLen++);

    PAPI_SET_VALUE_ENTRY_V2 pVal = NULL;
    if (dwVCnt > 1 && pwszParent && dwParLen)
        pVal = SearchApiSetHostV2(pArr, pVA, (PWSTR)pwszParent, (USHORT)dwParLen);
    if (!pVal)
        pVal = (PAPI_SET_VALUE_ENTRY_V2)((PBYTE)pVA + FIELD_OFFSET(API_SET_VALUE_ARRAY_V2, Array));
    if (!pVal) return FALSE;

    PWCHAR pwszRes = (PWCHAR)((PBYTE)pArr + MEM_RD(pVal, API_SET_VALUE_ENTRY_V2, ValueOffset));
    DWORD  dwResLen = MEM_RD(pVal, API_SET_VALUE_ENTRY_V2, ValueLength) / sizeof(WCHAR);
    if (dwResLen >= dwMax) return FALSE;

    for (DWORD i = 0; i < dwResLen; i++) pwszOut[i] = (WCHAR)MEM_RW_RAW(&pwszRes[i]);
    pwszOut[dwResLen] = L'\0';
    return TRUE;
}

static BOOL ResolveApiSet(IN PCWSTR pwszName, IN OPTIONAL PCWSTR pwszParent, OUT PWSTR pwszOut, IN DWORD dwMax)
{
    if (!pwszName || !pwszOut || !dwMax) return FALSE;
    DWORD dwLen = 0;
    for (dwLen = 0; pwszName[dwLen]; dwLen++);
    if (dwLen < 8) return FALSE;

    DWORD dwParLen = 0;
    if (pwszParent) for (dwParLen = 0; pwszParent[dwParLen]; dwParLen++);

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = NULL;
#endif
    if (!pPeb) return FALSE;

    PAPI_SET_NAMESPACE pMap = (PAPI_SET_NAMESPACE)MEM_RQ(pPeb, PEB, ApiSetMap);
    if (!pMap) return FALSE;

    DWORD dwVer = MEM_RD(pMap, API_SET_NAMESPACE, Version);

    switch (dwVer)
    {
        case API_SET_SCHEMA_VERSION_V2: return ResolveApiSetV2((PAPI_SET_NAMESPACE_ARRAY_V2)pMap, pwszName, pwszParent, pwszOut, dwMax);
        case API_SET_SCHEMA_VERSION_V3: return ResolveApiSetV3((PAPI_SET_NAMESPACE_ARRAY_V3)pMap, pwszName, pwszParent, pwszOut, dwMax);
        case API_SET_SCHEMA_VERSION_V4: return ResolveApiSetV4((PAPI_SET_NAMESPACE_ARRAY_V4)pMap, pwszName, pwszParent, pwszOut, dwMax);
        case API_SET_SCHEMA_VERSION_V6: return ResolveApiSetV6((PAPI_SET_NAMESPACE_V6)pMap, pwszName, pwszParent, pwszOut, dwMax);
        default: return FALSE;
    }
}

#pragma endregion


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region MODULE_AND_PROC_RESOLUTION


HMODULE ResolveModuleByHash(IN UINT32 uModuleNameHash)
{
    PPEB                    pPeb        = NtCurrentPeb();
    PPEB_LDR_DATA           pLdr        = NULL;
    PLDR_DATA_TABLE_ENTRY   pEntry      = NULL;
    PLIST_ENTRY             pHead       = NULL;
    PLIST_ENTRY             pCur        = NULL;
    ULONG_PTR               uNameAddr   = 0;
    PWCHAR                  pwzName     = NULL;

    if (!pPeb) return NULL;

    pLdr = (PPEB_LDR_DATA)MEM_RQ(pPeb, PEB, Ldr);
    if (!pLdr) return NULL;

    pHead = (PLIST_ENTRY)((ULONG_PTR)pLdr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    pCur  = (PLIST_ENTRY)MEM_RQ(pHead, LIST_ENTRY, Flink);
    pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!uModuleNameHash)
        return (HMODULE)MEM_RQ(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);

    while (pCur != pHead)
    {
        pEntry    = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        uNameAddr = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseDllName);
        pwzName   = (PWCHAR)GadgetReadQ(uNameAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));

        if (pwzName && uModuleNameHash == CRC32_WI(pwzName))
            return (HMODULE)MEM_RQ(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);

        pCur = (PLIST_ENTRY)MEM_RQ(pCur, LIST_ENTRY, Flink);
    }

    return NULL;
}


BOOL QueryModuleInfo(IN OPTIONAL HMODULE hModule, OUT OPTIONAL PWSTR pwszModuleName, OUT OPTIONAL PWSTR pwszFullPath)
{
    PWCHAR                  pwszSrcName     = NULL;
    PWCHAR                  pwszSrcPath     = NULL;
    USHORT                  usNameBytes     = 0;
    USHORT                  usPathBytes     = 0;
    DWORD                   dwNameChars     = 0;
    DWORD                   dwPathChars     = 0;
    PPEB                    pPeb            = NULL;
    PPEB_LDR_DATA           pLdr            = NULL;
    PLDR_DATA_TABLE_ENTRY   pEntry          = NULL;
    PLIST_ENTRY             pHead           = NULL;
    PLIST_ENTRY             pCur            = NULL;
    HMODULE                 hCur            = NULL;
    ULONG_PTR               uAddr          = 0;

    if (!pwszModuleName && !pwszFullPath) return FALSE;

    pPeb = NtCurrentPeb();
    if (!pPeb) return FALSE;

    if (!hModule)
        hModule = (HMODULE)MEM_RQ(pPeb, PEB, ImageBaseAddress);
    if (!hModule) return FALSE;

    pLdr = (PPEB_LDR_DATA)MEM_RQ(pPeb, PEB, Ldr);
    if (!pLdr) return FALSE;

    pHead = (PLIST_ENTRY)((ULONG_PTR)pLdr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    pCur  = (PLIST_ENTRY)MEM_RQ(pHead, LIST_ENTRY, Flink);

    while (pCur != pHead)
    {
        pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        hCur   = (HMODULE)MEM_RQ(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);

        if (hCur == hModule)
        {
            if (pwszModuleName)
            {
                uAddr       = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseDllName);
                usNameBytes = (USHORT)GadgetReadW(uAddr + FIELD_OFFSET(UNICODE_STRING, Length));
                pwszSrcName = (PWCHAR)GadgetReadQ(uAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));
            }

            if (pwszFullPath)
            {
                uAddr       = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName);
                usPathBytes = (USHORT)GadgetReadW(uAddr + FIELD_OFFSET(UNICODE_STRING, Length));
                pwszSrcPath = (PWCHAR)GadgetReadQ(uAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));
            }

            break;
        }

        pCur = (PLIST_ENTRY)MEM_RQ(pCur, LIST_ENTRY, Flink);
    }

    if (pwszModuleName)
    {
        if (!pwszSrcName || !usNameBytes) return FALSE;
        dwNameChars = usNameBytes / sizeof(WCHAR);
        if (dwNameChars >= MAX_PATH) return FALSE;
        for (DWORD i = 0; i < dwNameChars; i++)
            pwszModuleName[i] = (WCHAR)MEM_RW_RAW(&pwszSrcName[i]);
        pwszModuleName[dwNameChars] = L'\0';
    }

    if (pwszFullPath)
    {
        if (!pwszSrcPath || !usPathBytes) return FALSE;
        dwPathChars = usPathBytes / sizeof(WCHAR);
        if (dwPathChars >= MAX_PATH) return FALSE;
        for (DWORD i = 0; i < dwPathChars; i++)
            pwszFullPath[i] = (WCHAR)MEM_RW_RAW(&pwszSrcPath[i]);
        pwszFullPath[dwPathChars] = L'\0';
    }

    return TRUE;
}


FARPROC ResolveProcByHash(IN HMODULE hModule, IN UINT32 uFuncHash)
{
    PIMAGE_DOS_HEADER       pDos            = NULL;
    PIMAGE_NT_HEADERS       pNt             = NULL;
    PIMAGE_EXPORT_DIRECTORY pExp            = NULL;
    PIMAGE_DATA_DIRECTORY   pDir            = NULL;
    PDWORD                  pNames          = NULL;
    PDWORD                  pAddrs          = NULL;
    PWORD                   pOrds           = NULL;
    DWORD                   dwExpRva        = 0;
    DWORD                   dwExpSize       = 0;
    DWORD                   dwFuncRva       = 0;
    DWORD                   dwIdx           = 0;
    FARPROC                 pFunc           = NULL;

    if (!hModule || !uFuncHash) return NULL;

    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (MEM_RW(pDos, IMAGE_DOS_HEADER, e_magic) != IMAGE_DOS_SIGNATURE) return NULL;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + MEM_RD(pDos, IMAGE_DOS_HEADER, e_lfanew));
    if (MEM_RD(pNt, IMAGE_NT_HEADERS, Signature) != IMAGE_NT_SIGNATURE) return NULL;

    pDir = (PIMAGE_DATA_DIRECTORY)((ULONG_PTR)pNt + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, DataDirectory) + (IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)));

    dwExpRva  = MEM_RD(pDir, IMAGE_DATA_DIRECTORY, VirtualAddress);
    dwExpSize = MEM_RD(pDir, IMAGE_DATA_DIRECTORY, Size);
    if (!dwExpRva || !dwExpSize) return NULL;

    pExp   = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + dwExpRva);
    pAddrs = (PDWORD)((PBYTE)hModule + MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, AddressOfFunctions));

    if (HIWORD(uFuncHash) == 0)
    {
        WORD    wOrd    = LOWORD(uFuncHash);
        DWORD   dwBase  = MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, Base);
        DWORD   dwNum   = MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, NumberOfFunctions);

        if (wOrd < dwBase || wOrd >= dwBase + dwNum) return NULL;

        dwFuncRva = MEM_RD_RAW(&pAddrs[wOrd - dwBase]);
    }
    else
    {
        DWORD dwNamesRva    = MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, AddressOfNames);
        DWORD dwOrdsRva     = MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals);
        DWORD dwNumNames    = MEM_RD(pExp, IMAGE_EXPORT_DIRECTORY, NumberOfNames);

        pNames = (PDWORD)((PBYTE)hModule + dwNamesRva);
        pOrds  = (PWORD)((PBYTE)hModule + dwOrdsRva);

        for (dwIdx = 0; dwIdx < dwNumNames; dwIdx++)
        {
            CHAR    szName[BUFFER_SIZE_1024] = { 0 };
            PCHAR   pName = (PCHAR)((PBYTE)hModule + MEM_RD_RAW(&pNames[dwIdx]));
            DWORD   ci    = 0;

            for (; ci < BUFFER_SIZE_1024 - 1; ci++)
            {
                CHAR c = (CHAR)MEM_RW_RAW(&pName[ci]);
                szName[ci] = c;
                if (!c) break;
            }
            szName[BUFFER_SIZE_1024 - 1] = '\0';

            if (uFuncHash == CRC32_A(szName))
            {
                dwFuncRva = MEM_RD_RAW(&pAddrs[MEM_RW_RAW(&pOrds[dwIdx])]);
                break;
            }
        }

        if (dwIdx == dwNumNames) return NULL;
    }

    if (!dwFuncRva) return NULL;

    pFunc = (FARPROC)((PBYTE)hModule + dwFuncRva);

    // Forwarded export handling
    if (dwFuncRva >= dwExpRva && dwFuncRva < (dwExpRva + dwExpSize))
    {
        CHAR    szFwd[MAX_PATH]     = { 0 };
        WCHAR   wszLib[MAX_PATH]    = { 0 };
        PCHAR   pFwd                = (PCHAR)pFunc;
        DWORD   dwDot               = 0;
        HMODULE hFwd                = NULL;

        while ((PBYTE)&pFwd[dwDot] < ((PBYTE)pExp + dwExpSize))
        {
            CHAR c = (CHAR)MEM_RW_RAW(&pFwd[dwDot]);
            if (c == '\0' || c == '.') break;
            dwDot++;
        }

        if ((PBYTE)&pFwd[dwDot] >= ((PBYTE)pExp + dwExpSize) || (CHAR)MEM_RW_RAW(&pFwd[dwDot]) != '.')
            return NULL;

        if (dwDot == 0 || dwDot >= MAX_PATH - 5) return NULL;

        for (DWORD i = 0; i < dwDot; i++)
            wszLib[i] = (UCHAR)MEM_RW_RAW(&pFwd[i]);

        wszLib[dwDot]     = L'.';
        wszLib[dwDot + 1] = L'd';
        wszLib[dwDot + 2] = L'l';
        wszLib[dwDot + 3] = L'l';
        wszLib[dwDot + 4] = L'\0';

        {
            WCHAR c0 = wszLib[0] | 0x20;
            WCHAR c1 = wszLib[1] | 0x20;
            WCHAR c2 = wszLib[2] | 0x20;

            if (((c0 == L'a' && c1 == L'p' && c2 == L'i') || (c0 == L'e' && c1 == L'x' && c2 == L't')) && wszLib[3] == L'-')
            {
                WCHAR   wszPar[MAX_PATH] = { 0 };
                PWSTR   pwszP = NULL;

                if (QueryModuleInfo(hModule, wszPar, NULL))
                    pwszP = wszPar;

                if (!ResolveApiSet(wszLib, pwszP, wszLib, MAX_PATH))
                    return NULL;
            }
        }

        for (DWORD i = 0; (PBYTE)&pFwd[dwDot + 1 + i] < ((PBYTE)pExp + dwExpSize) && i < MAX_PATH - 1; i++)
        {
            CHAR c = (CHAR)MEM_RW_RAW(&pFwd[dwDot + 1 + i]);
            if (!c) break;
            szFwd[i] = c;
        }

        if (!szFwd[0]) return NULL;

        if (!(hFwd = ResolveModuleByHash(CRC32_WI(wszLib))))
        {
            if (!(hFwd = LoadLibraryW(wszLib)))
                return NULL;
        }

        if (szFwd[0] == '#')
        {
            DWORD dwOrd = 0;
            if (!szFwd[1]) return NULL;
            for (DWORD i = 1; szFwd[i]; i++)
            {
                if (szFwd[i] >= '0' && szFwd[i] <= '9')
                {
                    dwOrd = dwOrd * 10 + (szFwd[i] - '0');
                    if (dwOrd > 0xFFFF) return NULL;
                }
                else return NULL;
            }
            return ResolveProcByHash(hFwd, (UINT32)(WORD)dwOrd);
        }
        else
        {
            return ResolveProcByHash(hFwd, CRC32_A(szFwd));
        }
    }

    return pFunc;
}


#pragma endregion
