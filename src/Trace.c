#include "Trace.h"

BOOL g_bVerbose = FALSE;

VOID TraceLog(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...)
{
    DWORD       dwSavedError                = 0;
    INT         cchWritten                  = 0;
    CHAR        szBuffer[BUFFER_SIZE_2048]  = { 0 };
    va_list     pszVaArgs                   = NULL;

    dwSavedError = GetLastError();

    va_start(pszVaArgs, pszFmt);
    cchWritten = wvsprintfA(szBuffer, pszFmt, pszVaArgs);
    va_end(pszVaArgs);

    if (cchWritten < 0)
        goto _END;

    if (cchWritten < BUFFER_SIZE_2048 - 1)
        wsprintfA(szBuffer + cchWritten, "     [%s:%d]\n", pszFile, nLine);
    else
    {
        szBuffer[BUFFER_SIZE_2048 - 5] = '.';
        szBuffer[BUFFER_SIZE_2048 - 4] = '.';
        szBuffer[BUFFER_SIZE_2048 - 3] = '.';
        szBuffer[BUFFER_SIZE_2048 - 2] = '\n';
        szBuffer[BUFFER_SIZE_2048 - 1] = '\0';
    }

    OutputDebugStringA(szBuffer);
    if (g_bVerbose)
    {
        DWORD dwWritten = 0;
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, (DWORD)lstrlenA(szBuffer), &dwWritten, NULL);
    }

_END:
    SetLastError(dwSavedError);
}
