#pragma once
#include <ntifs.h>  // 一定要在<ntddk.h>前面
#include <ntddk.h>
#include <ntdef.h>

#pragma pack(1)
#ifdef _WIN64
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG    ServiceTableBase;  // SSDT基地址
	// 此域用于操作系统的 checked builds, 
	// 包含着SSDT中每个服务被调用次数的计数器。
	// 这个计数器由 INT 2Eh 处理程序 (KiSystemService)更新
	PVOID     ServiceCounterTableBase;
	ULONGLONG NumberOfServices;  // 由 ServiceTableBase 描述的服务的数目
	PVOID     ParamTableBase;    // 包含每个系统服务参数字节数表的基地址
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;
#else // WIN32
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;  // SSDT基地址
	// 此域用于操作系统的 checked builds, 
	// 包含着SSDT中每个服务被调用次数的计数器。
	// 这个计数器由 INT 2Eh 处理程序 (KiSystemService)更新
	PULONG ServiceCounterTableBase; // SSDT中服务被调用次数计数器
	ULONG  NumberOfServices;  // 由 ServiceTableBase 描述的服务的数目
	PUCHAR ParamTableBase;    // 包含每个系统服务参数字节数表的基地址
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;
#endif
#pragma pack()


#ifndef _WIN64
extern __declspec(dllimport) KESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable; //导入全局变量
#endif


#pragma region WINNT
// 
// 从winnt.h中复制出来的结构体
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

// 微软未文档化SDK

// 函数指针
typedef NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE processHandle,
	ACCESS_MASK desiredAccess,
	POBJECT_ATTRIBUTES objectAttributes,
	PCLIENT_ID clientId);


// 声明
PCHAR PsGetProcessImageFileName(PEPROCESS Process);