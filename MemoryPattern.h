#pragma once
#include <ntdef.h>

#define FIND_SIG_DEFAULT_LENGTH  4096L

/**
 * pattern: "\xAA\xBB???\x56", `?` ´ú±í\xFF
 * 
 */
//BOOLEAN FindMAByPattern(IN const std::string& pattern, 
//	IN ULONG ulStartAddr, 
//	IN ULONG count, 
//	OUT ULONG& ulFoundAddr);


PVOID64 FindSignature2(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg, IN ULONG64 ulScanSize, IN CHAR wildcard);
PVOID64 FindSignature1(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg, IN ULONG64 ulScanSize);
PVOID64 FindSignature(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg);
