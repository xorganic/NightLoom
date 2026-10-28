#pragma once
#ifndef TRACE_H
#define TRACE_H

#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define _TRACE_FORCE

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifndef BUFFER_SIZE_2048
#define BUFFER_SIZE_2048        2048
#endif

#ifndef GET_FILENAMEA
#define GET_FILENAMEA(PATHA)   PathFindFileNameA(PATHA)
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    extern BOOL g_bVerbose;
    VOID TraceLog(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#if defined(_DEBUG) || defined(_TRACE_FORCE)
#define TRACE(fmt, ...)     TraceLog(GET_FILENAMEA(__FILE__), __LINE__, fmt, ##__VA_ARGS__)
#else
#define TRACE(fmt, ...)     ((void)0)
#endif


#endif // !TRACE_H
