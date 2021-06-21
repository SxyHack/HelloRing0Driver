#pragma once

#include "ntdll2.h"

// 关闭页面写保护
void ClosePageWriteProtect();
// 恢复页面写保护
void ResetPageWriteProtect();

// 方法2
void ClosePageWrite64(KIRQL* rql);
void ResetPageWrite64(KIRQL rql);

// 获取SSDT, 支持WIN10 ver18362.19h1
// 1. rdmsr c0000082
// 2. KiSystemCall64Shadow
// 3. KiSystemServiceUser
// 4. KiSSDT
PKESERVICE_DESCRIPTOR_TABLE GetSSDTEntryPtr();

// 获取 SSDT 函数地址
PVOID GetSSDTFunction(PCHAR pszFunctionName, PULONG64 pFunctionID);
ULONG GetSSDTFunctionIndex(UNICODE_STRING usFilename, PCHAR pszFunctionName);

void SetSSDTFunction(PKESERVICE_DESCRIPTOR_TABLE pSSDT, ULONG64 ulFuncID, ULONG64 ulHookFunctionAddr);

// 声明 Hook Functions
//NTSTATUS NTAPI HK_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
