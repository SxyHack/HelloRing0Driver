#pragma once

#include "ntdll.h"


// 关闭页面写保护
void ClosePageWriteProtect();

// 恢复页面写保护
void ResetPageWriteProtect();

PKESERVICE_DESCRIPTOR_TABLE GetSSDTAddress();

// 获取 SSDT 函数地址
PVOID GetSSDTFunctionAddr(PCHAR pszFunctionName);
ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);