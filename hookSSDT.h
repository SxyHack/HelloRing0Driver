#pragma once

#include "ntdll.h"


// �ر�ҳ��д����
void ClosePageWriteProtect();

// �ָ�ҳ��д����
void ResetPageWriteProtect();

PKESERVICE_DESCRIPTOR_TABLE GetSSDTAddress();

// ��ȡ SSDT ������ַ
PVOID GetSSDTFunctionAddr(PCHAR pszFunctionName);
ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);