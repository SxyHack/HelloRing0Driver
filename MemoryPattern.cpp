#include "MemoryPattern.h"
#include <ntddk.h>

#define FIND_MAX_SIZE 4096

typedef unsigned long  DWORD;
typedef unsigned short WORD;
typedef unsigned char  BYTE;

PVOID64 FindSignature2(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg, IN ULONG64 ulScanSize, IN CHAR chWildcard /*= '?'*/)
{
	BOOLEAN bFound = FALSE;
	ULONG64 ulAddressEnd = ulAddressBeg + ulScanSize;

	BOOLEAN bValid = MmIsAddressValid((PVOID)ulAddressBeg);
	PULONG64 pBeg = (PULONG64)ulAddressBeg;

	DbgPrint("Valid: %d %X", bValid, pBeg);

	for (BYTE* i = (BYTE*)ulAddressBeg; i < (BYTE*)(ulAddressEnd - pattern.Length); ++i)
	{
		bFound = TRUE;

		for (int j = 0; j < pattern.Length; ++j)
		{
			CHAR a = pattern.Buffer[j];
			CHAR b = i[j];
			if (a != b && a != chWildcard)
			{
				bFound = FALSE;
				break;
			}
		}

		if (bFound)
		{
			return (PVOID64)i;
		}
	}

	return 0;
}

PVOID64 FindSignature1(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg, IN ULONG64 ulScanSize)
{
	return FindSignature2(pattern, ulAddressBeg, ulScanSize, '?');
}

PVOID64 FindSignature(IN ANSI_STRING pattern, IN ULONG64 ulAddressBeg)
{
	return FindSignature2(pattern, ulAddressBeg, 4096, '?');
}

