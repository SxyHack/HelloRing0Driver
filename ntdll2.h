#pragma once
#include <ntifs.h>  // һ��Ҫ��<ntddk.h>ǰ��
#include <ntddk.h>
#include <ntdef.h>


#if DBG
#define kprintf(...) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TestHook.sys: "); \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, __VA_ARGS__)
#else
#define kprintf(...)
#endif

#pragma pack(1)
#ifdef _WIN64
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG    ServiceTableBase;  // SSDT����ַ
	// �������ڲ���ϵͳ�� checked builds, 
	// ������SSDT��ÿ�����񱻵��ô����ļ�������
	// ����������� INT 2Eh ������� (KiSystemService)����
	PVOID     ServiceCounterTableBase;
	ULONGLONG NumberOfServices;  // �� ServiceTableBase �����ķ������Ŀ
	PVOID     ParamTableBase;    // ����ÿ��ϵͳ��������ֽ�����Ļ���ַ
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;
#else // WIN32
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;  // SSDT����ַ
	// �������ڲ���ϵͳ�� checked builds, 
	// ������SSDT��ÿ�����񱻵��ô����ļ�������
	// ����������� INT 2Eh ������� (KiSystemService)����
	PULONG ServiceCounterTableBase; // SSDT�з��񱻵��ô���������
	ULONG  NumberOfServices;  // �� ServiceTableBase �����ķ������Ŀ
	PUCHAR ParamTableBase;    // ����ÿ��ϵͳ��������ֽ�����Ļ���ַ
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;
#endif
#pragma pack()


#ifndef _WIN64
extern __declspec(dllimport) KESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable; //����ȫ�ֱ���
#endif


#pragma region WINNT
// 
// ��winnt.h�и��Ƴ����Ľṹ��
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	USHORT e_magic;                     // Magic number
	USHORT e_cblp;                      // Bytes on last page of file
	USHORT e_cp;                        // Pages in file
	USHORT e_crlc;                      // Relocations
	USHORT e_cparhdr;                   // Size of header in paragraphs
	USHORT e_minalloc;                  // Minimum extra paragraphs needed
	USHORT e_maxalloc;                  // Maximum extra paragraphs needed
	USHORT e_ss;                        // Initial (relative) SS value
	USHORT e_sp;                        // Initial SP value
	USHORT e_csum;                      // Checksum
	USHORT e_ip;                        // Initial IP value
	USHORT e_cs;                        // Initial (relative) CS value
	USHORT e_lfarlc;                    // File address of relocation table
	USHORT e_ovno;                      // Overlay number
	USHORT e_res[4];                    // Reserved words
	USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;                   // OEM information; e_oemid specific
	USHORT e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT  MajorVersion;
	USHORT  MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;     // RVA from base of image
	ULONG   AddressOfNames;         // RVA from base of image
	ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;


//
// File header format.
//

typedef struct _IMAGE_FILE_HEADER {
	USHORT  Machine;
	USHORT  NumberOfSections;
	ULONG   TimeDateStamp;
	ULONG   PointerToSymbolTable;
	ULONG   NumberOfSymbols;
	USHORT  SizeOfOptionalHeader;
	USHORT  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//
	USHORT  Magic;
	UCHAR   MajorLinkerVersion;
	UCHAR   MinorLinkerVersion;
	ULONG   SizeOfCode;
	ULONG   SizeOfInitializedData;
	ULONG   SizeOfUninitializedData;
	ULONG   AddressOfEntryPoint;
	ULONG   BaseOfCode;
	ULONG   BaseOfData;

	//
	// NT additional fields.
	//
	ULONG   ImageBase;
	ULONG   SectionAlignment;
	ULONG   FileAlignment;
	USHORT  MajorOperatingSystemVersion;
	USHORT  MinorOperatingSystemVersion;
	USHORT  MajorImageVersion;
	USHORT  MinorImageVersion;
	USHORT  MajorSubsystemVersion;
	USHORT  MinorSubsystemVersion;
	ULONG   Win32VersionValue;
	ULONG   SizeOfImage;
	ULONG   SizeOfHeaders;
	ULONG   CheckSum;
	USHORT  Subsystem;
	USHORT  DllCharacteristics;
	ULONG   SizeOfStackReserve;
	ULONG   SizeOfStackCommit;
	ULONG   SizeOfHeapReserve;
	ULONG   SizeOfHeapCommit;
	ULONG   LoaderFlags;
	ULONG   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

//
// Optional header format x64.
//
typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT      Magic;
	UCHAR       MajorLinkerVersion;
	UCHAR       MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT      MajorOperatingSystemVersion;
	USHORT      MinorOperatingSystemVersion;
	USHORT      MajorImageVersion;
	USHORT      MinorImageVersion;
	USHORT      MajorSubsystemVersion;
	USHORT      MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT      Subsystem;
	USHORT      DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

#pragma endregion

// ΢��δ�ĵ���SDK

// ����ָ��
typedef NTSTATUS(NTAPI* _NtOpenProcess)(
	OUT PHANDLE processHandle,
	IN ACCESS_MASK desiredAccess,
	IN POBJECT_ATTRIBUTES objectAttributes,
	IN PCLIENT_ID clientId);

typedef NTSTATUS(NTAPI* _NtCreateFile)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength);


// ����
EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);