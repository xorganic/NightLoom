#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include <Strsafe.h>
#include <intrin.h>
#include <immintrin.h>

#include "NtDefs.h"
#include "Trace.h"

#pragma comment(lib, "Shlwapi.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define BUFFER_SIZE_512                 512
#define BUFFER_SIZE_1024                1024
#define BUFFER_SIZE_2048                2048
#define BUFFER_SIZE_4096                4096

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// CRC-32B hashes — case-sensitive API names, case-insensitive module names

#define CRC32B_NTQUERYSYSTEMINFORMATION         0x97FD2398
#define CRC32B_NTOPENPROCESS                    0xDBF381B5
#define CRC32B_NTQUERYINFORMATIONPROCESS        0xA5C44C50
#define CRC32B_NTCLOSE                          0x0D09C750
#define CRC32B_NTQUERYVIRTUALMEMORY             0x03F6F38C
#define CRC32B_NTPROTECTVIRTUALMEMORY           0x5C2D1A97
#define CRC32B_NTREADVIRTUALMEMORY              0x81223212
#define CRC32B_NTALLOCATEVIRTUALMEMORY          0xE0762FEB
#define CRC32B_NTWRITEVIRTUALMEMORY             0xE4879939
#define CRC32B_NTCREATESECTION                  0x9EEE4B80
#define CRC32B_NTMAPVIEWOFSECTION               0xA4163EBC
#define CRC32B_NTUNMAPVIEWOFSECTION             0x90483FF6

// API hashes (case-sensitive)
#define CRC32B_CREATETHREAD                     0x906A06B0
#define CRC32B_CREATEACTCTXWWORKER              0x75231A0C

// Module hashes (case-insensitive)
#define CRC32B_NTDLLDLL                         0x84C05E40
#define CRC32B_KERNEL32DLL                      0x6AE69F02

#endif // !COMMON_H
