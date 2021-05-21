#include "hookSSDT.h"
#include "MemoryPattern.h"
#include "page.h"

#include <intrin.h>

#pragma intrinsic(__readmsr)

void ClosePageWriteProtect()
{
#ifdef _WIN64
	CloseProtect64();
#else
	__asm {
		push eax
		mov eax, cr0
		and eax, 0xFFFEFFFF
		mov cr0, eax
		pop eax
	}
#endif
}

void ResetPageWriteProtect()
{
#ifdef _WIN64
	ResetProtect64();
#else
	__asm {
		push eax
		mov eax, cr0
		or  eax, NOT 0xFFFEFFFF
		mov cr0, eax
		pop eax
	}
#endif
}


void ClosePageWrite64(KIRQL* KiRQL)
{
	UINT64 CR0 = __readcr0();
	CR0 &= ~0x10000;
	__writecr0(CR0);
	_disable();

	*KiRQL = KeRaiseIrqlToDpcLevel();
}

void ResetPageWrite64(KIRQL KiRQL)
{
	UINT64 CR0 = __readcr0();
	CR0 |= 0x10000;
	_enable();
	__writecr0(CR0);
	KeLowerIrql(KiRQL);
}

PKESERVICE_DESCRIPTOR_TABLE GetSSDTEntryPtr()
{
#ifdef _WIN64
	ULONG64 ulOutAddr = 0;
	ULONG64 ulKiSystemServiceUserAddr = 0xFFFFFFFFFFFFFFFF;
	ULONG64 ulKiSSDTAddr = 0;
	PVOID64 pSig1, pSig2 = NULL;
	ANSI_STRING strSig1, strSig2;

	// ��ȡC0000082�Ĵ���,��ȡ�� KiSystemCall64Shadow ������ַ
	ULONG64 ulKiSystemCall64ShadowAddr = (ULONG64)__readmsr(0xC0000082);
	RtlInitAnsiString(&strSig1, "\x0F\xAE\xE8\x65????????\xE9????\xC3");
	if (!MmIsAddressValid((PVOID)ulKiSystemCall64ShadowAddr))
	{
		return NULL;
	}

	// ����������
	if ((pSig1 = FindSignature(strSig1, ulKiSystemCall64ShadowAddr)) == NULL) {
		return NULL;
	}

	ulOutAddr = (ULONG64)pSig1 + 13L;
	RtlCopyMemory(&ulKiSystemServiceUserAddr, (PUCHAR)ulOutAddr, 4);
	ulKiSystemServiceUserAddr += ulOutAddr;
	ulKiSystemServiceUserAddr += 5;

	if (!MmIsAddressValid((PVOID)ulKiSystemServiceUserAddr)) {
		return NULL;
	}

	RtlInitAnsiString(&strSig2, "\x4C\x8D\x15????");
	// ����������
	if ((pSig2 = FindSignature(strSig2, ulKiSystemServiceUserAddr)) == NULL) {
		return NULL;
	}

	ulOutAddr = (ULONG64)pSig2;
	RtlCopyMemory(&ulKiSSDTAddr, (PUCHAR)(ulOutAddr + 3L), 4);
	ulKiSSDTAddr += ulOutAddr;
	ulKiSSDTAddr += 7;

	return (PKESERVICE_DESCRIPTOR_TABLE)ulKiSSDTAddr;
#else
	return &KeServiceDescriptorTable;
#endif
}

PVOID GetSSDTFunction(PCHAR pszFunctionName, PULONG64 pFunctionID)
{
	UNICODE_STRING ucNTDLL;
	ULONG ulSSDTFunctionIndex = 0;
	PVOID pFunctionAddress = NULL;
	RtlInitUnicodeString(&ucNTDLL, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	// �� ntdll.dll �л�ȡSSDT����������
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ucNTDLL, pszFunctionName);

#ifdef _WIN64
	PKESERVICE_DESCRIPTOR_TABLE pServiceDescriptorTable = GetSSDTEntryPtr();
	// ����������, ��SSDT���л�ȡ��Ӧ����ƫ�Ƶ�ַ�������������ַ
	ULONG64 ulFunc   = pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex];
	ULONG64 ulOffset = ulFunc >> 4;
	pFunctionAddress = (PVOID)((PUCHAR)pServiceDescriptorTable->ServiceTableBase + ulOffset);
	*pFunctionID     = ulSSDTFunctionIndex;
	// ��ʾ
	kprintf("[%s][SSDT:0x%p][Index:%d][Address:0x%p Offset:%I64d]\n", pszFunctionName, 
		pServiceDescriptorTable, ulSSDTFunctionIndex, pFunctionAddress, ulOffset);
#else
	// ����������, ��SSDT���л�ȡ��Ӧ������ַ
	pFunctionAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
	// ��ʾ
	kprintf("[%s][Index:%d][Address:0x%p]\n", pszFunctionName, ulSSDTFunctionIndex, pFunctionAddress);
#endif

	return pFunctionAddress;
}

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE* phFile, HANDLE* phSection, PVOID* ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	// �� DLL �ļ�, ����ȡ�ļ����
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		kprintf("ZwOpenFile Error! [error code: 0x%X]", status);
		return status;
	}
	// ����һ���ڶ���, �� PE �ṹ�е� SectionALignment ��С����ӳ���ļ�
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		kprintf("ZwCreateSection Error! [error code: 0x%X]", status);
		return status;
	}

	// ӳ�䵽�ڴ�
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		kprintf("ZwMapViewOfSection Error! [error code: 0x%X]", status);
		return status;
	}
	// ��������
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;
	return status;
}

// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// �����Ƶĵ�����������
	ULONG  ulNumberOfNames = pExportTable->NumberOfNames;
	// �����������Ƶ�ַ��
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR  lpName = NULL;
	// ��ʼ����������
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// �ж��Ƿ���ҵĺ���
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// ��ȡ����������ַ
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// ��ȡ SSDT ���� Index
#ifdef _WIN64
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 4);
#else
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
#endif
			break;
		}
	}
	return ulFunctionIndex;
}

ULONG GetSSDTFunctionIndex(UNICODE_STRING binaryFilePath, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	// �ڴ�ӳ���ļ�
	status = DllFileMap(binaryFilePath, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		kprintf("DllFileMap Error!\n");
		return ulFunctionIndex;
	}
	// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);

	// �ͷ�
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);
	return ulFunctionIndex;
}

void SetSSDTFunction(PKESERVICE_DESCRIPTOR_TABLE pSSDT, ULONG64 ulFuncID, ULONG64 ulHookFunctionAddr)
{
	if (pSSDT == NULL)
		return;

	ULONG64 ulBase = (ULONG64)pSSDT->ServiceTableBase;
	ULONG uOffset = (ULONG)(ulHookFunctionAddr - ulBase);
	pSSDT->ServiceTableBase[ulFuncID] = (uOffset << 4);
}

