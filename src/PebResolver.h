#ifndef PEB_RESOLVER_H
#define PEB_RESOLVER_H

#include "Common.h"
#include "MemReadGadget.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    UINT32 Crc32bHashA(IN PCHAR pszString);
    UINT32 Crc32bHashAI(IN PCHAR pszString);

    UINT32 Crc32bHashW(IN PWCHAR pwszString);
    UINT32 Crc32bHashWI(IN PWCHAR pwszString);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define CRC32_A(STR)        Crc32bHashA((PCHAR)(STR))
#define CRC32_AI(STR)       Crc32bHashAI((PCHAR)(STR))

#define CRC32_W(STR)        Crc32bHashW((PWCHAR)(STR))
#define CRC32_WI(STR)       Crc32bHashWI((PWCHAR)(STR))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    HMODULE ResolveModuleByHash(IN UINT32 uModuleNameHash);

    BOOL QueryModuleInfo(IN OPTIONAL HMODULE hModule, OUT OPTIONAL PWSTR pwszModuleName, OUT OPTIONAL PWSTR pwszFullPath);

    FARPROC ResolveProcByHash(IN HMODULE hModule, IN UINT32 uFunctionNameHash);

#ifdef __cplusplus
}
#endif


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region API_SET_DEFINITIONS

#define API_SET_SCHEMA_VERSION_V2       0x00000002
#define API_SET_SCHEMA_VERSION_V3       0x00000003
#define API_SET_SCHEMA_VERSION_V4       0x00000004
#define API_SET_SCHEMA_VERSION_V6       0x00000006

#define API_SET_PREFIX_API              (ULONGLONG)0x002D004900500041 /* L"api-" */
#define API_SET_PREFIX_EXT              (ULONGLONG)0x002D005400580045 /* L"ext-" */

#define CHAR_TO_LOWER_W(wc)            (((WCHAR)((wc) - L'A') <= (L'Z' - L'A')) ? ((wc) | 0x20) : (wc))

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE_V6, * PAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, * PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_HASH_ENTRY_V6 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY_V6, * PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, * PAPI_SET_VALUE_ENTRY_V6;

typedef const API_SET_VALUE_ENTRY_V6* PCAPI_SET_VALUE_ENTRY_V6;
typedef const API_SET_HASH_ENTRY_V6* PCAPI_SET_HASH_ENTRY_V6;
typedef const API_SET_NAMESPACE_ENTRY_V6* PCAPI_SET_NAMESPACE_ENTRY_V6;
typedef const API_SET_NAMESPACE_V6* PCAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V4, * PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4 {
    ULONG Flags;
    ULONG Count;
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, * PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V4, * PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, * PAPI_SET_NAMESPACE_ARRAY_V4;

typedef const API_SET_VALUE_ENTRY_V4* PCAPI_SET_VALUE_ENTRY_V4;
typedef const API_SET_VALUE_ARRAY_V4* PCAPI_SET_VALUE_ARRAY_V4;
typedef const API_SET_NAMESPACE_ENTRY_V4* PCAPI_SET_NAMESPACE_ENTRY_V4;
typedef const API_SET_NAMESPACE_ARRAY_V4* PCAPI_SET_NAMESPACE_ARRAY_V4;

typedef struct _API_SET_VALUE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V3, * PAPI_SET_VALUE_ENTRY_V3;

typedef struct _API_SET_VALUE_ARRAY_V3 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V3, * PAPI_SET_VALUE_ARRAY_V3;

typedef struct _API_SET_NAMESPACE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V3, * PAPI_SET_NAMESPACE_ENTRY_V3;

typedef struct _API_SET_NAMESPACE_ARRAY_V3 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V3, * PAPI_SET_NAMESPACE_ARRAY_V3;

typedef const API_SET_VALUE_ENTRY_V3* PCAPI_SET_VALUE_ENTRY_V3;
typedef const API_SET_VALUE_ARRAY_V3* PCAPI_SET_VALUE_ARRAY_V3;
typedef const API_SET_NAMESPACE_ENTRY_V3* PCAPI_SET_NAMESPACE_ENTRY_V3;
typedef const API_SET_NAMESPACE_ARRAY_V3* PCAPI_SET_NAMESPACE_ARRAY_V3;

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, * PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, * PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V2, * PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, * PAPI_SET_NAMESPACE_ARRAY_V2;

typedef const API_SET_VALUE_ENTRY_V2* PCAPI_SET_VALUE_ENTRY_V2;
typedef const API_SET_VALUE_ARRAY_V2* PCAPI_SET_VALUE_ARRAY_V2;
typedef const API_SET_NAMESPACE_ENTRY_V2* PCAPI_SET_NAMESPACE_ENTRY_V2;
typedef const API_SET_NAMESPACE_ARRAY_V2* PCAPI_SET_NAMESPACE_ARRAY_V2;

#pragma endregion


#endif // !PEB_RESOLVER_H
