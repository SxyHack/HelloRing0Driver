#pragma once

#include "ntdll2.h"

// �ر�ҳ��д����
void ClosePageWriteProtect();
// �ָ�ҳ��д����
void ResetPageWriteProtect();

// ����2
void ClosePageWrite64(KIRQL* rql);
void ResetPageWrite64(KIRQL rql);

// ��ȡSSDT, ֧��WIN10 ver18362.19h1
// 1. rdmsr c0000082
// 2. KiSystemCall64Shadow
// 3. KiSystemServiceUser
// 4. KiSSDT
PKESERVICE_DESCRIPTOR_TABLE GetSSDTEntryPtr();

// ��ȡ SSDT ������ַ
PVOID GetSSDTFunction(PCHAR pszFunctionName, PULONG64 pFunctionID);
ULONG GetSSDTFunctionIndex(UNICODE_STRING usFilename, PCHAR pszFunctionName);

void SetSSDTFunction(PKESERVICE_DESCRIPTOR_TABLE pSSDT, ULONG64 ulFuncID, ULONG64 ulHookFunctionAddr);

// ���� Hook Functions
//NTSTATUS NTAPI HK_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
