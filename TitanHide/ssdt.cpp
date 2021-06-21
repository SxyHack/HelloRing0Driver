#include "ssdt.h"
#include "undocumented.h"
#include "pe.h"
#include "log.h"
#include "ntdll.h"

//structures
struct SSDTStruct
{
    LONG* pServiceTable;
    PVOID pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR pArgumentTable;
};

//Based on: https://github.com/hfiref0x/WinObjEx64
static SSDTStruct* SSDTfind()
{
    static SSDTStruct* SSDT = 0;
    if(!SSDT)
    {
#ifndef _WIN64
        //x86 code
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
        //x64 code
        ULONG kernelSize;
        ULONG_PTR kernelBase = (ULONG_PTR)Undocumented::GetKernelBase(&kernelSize);
        if(kernelBase == 0 || kernelSize == 0)
            return nullptr;

        // Find .text section
        PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
        PIMAGE_SECTION_HEADER textSection = nullptr;
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for(ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
            RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            if(strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
            {
                textSection = section;
                break;
            }
            section++;
        }
        if(textSection == nullptr)
            return nullptr;

        // Find KiSystemServiceStart in .text
        const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
        bool found = false;
        ULONG KiSSSOffset;
        for(KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
        {
            if(RtlCompareMemory(((unsigned char*)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
            {
                found = true;
                break;
            }
        }
        if(!found)
            return nullptr;

        // lea r10, KeServiceDescriptorTable
        ULONG_PTR address = kernelBase + textSection->VirtualAddress + KiSSSOffset + signatureSize;
        LONG relativeOffset = 0;
        if((*(unsigned char*)address == 0x4c) &&
                (*(unsigned char*)(address + 1) == 0x8d) &&
                (*(unsigned char*)(address + 2) == 0x15))
        {
            relativeOffset = *(LONG*)(address + 3);
        }
        if(relativeOffset == 0)
            return nullptr;

        SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
    }
    return SSDT;
}

PVOID SSDT::GetFunctionAddress(const char* apiname)
{
    //read address from SSDT
    SSDTStruct* SSDT = SSDTfind();
    if(!SSDT)
    {
        Log("[TITANHIDE] SSDT not found...\r\n");
        return 0;
    }
    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        Log("[TITANHIDE] ServiceTable not found...\r\n");
        return 0;
    }
    ULONG readOffset = NTDLL::GetExportSsdtIndex(apiname);
    if(readOffset == -1)
        return 0;
    if(readOffset >= SSDT->NumberOfServices)
    {
        Log("[TITANHIDE] Invalid read offset...\r\n");
        return 0;
    }
#ifdef _WIN64
    return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
    return (PVOID)SSDT->pServiceTable[readOffset];
#endif
}

#ifdef _WIN64
static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize)
{
    unsigned char* Code = (unsigned char*)CodeStart;

    for(unsigned int i = 0, j = 0; i < CodeSize; i++)
    {
        if(Code[i] == 0x90 || Code[i] == 0xCC)  //NOP or INT3
            j++;
        else
            j = 0;
        if(j == CaveSize)
            return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
    }
    return 0;
}
#endif //_WIN64

HOOK SSDT::Hook(const char* apiname, void* newfunc)
{
    SSDTStruct* SSDT = SSDTfind();
    if(!SSDT)
    {
        Log("[TITANHIDE] SSDT not found...\r\n");
        return 0;
    }
    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        Log("[TITANHIDE] ServiceTable not found...\r\n");
        return 0;
    }
    int FunctionIndex = NTDLL::GetExportSsdtIndex(apiname);
    if(FunctionIndex == -1)
        return 0;
    if((ULONGLONG)FunctionIndex >= SSDT->NumberOfServices)
    {
        Log("[TITANHIDE] Invalid API offset...\r\n");
        return 0;
    }

    HOOK hHook = 0;
    LONG oldValue = SSDT->pServiceTable[FunctionIndex];
    LONG newValue;

#ifdef _WIN64
    /*
    x64 SSDT Hook;
    1) find API addr
    2) get code page+size
    3) find cave address
    4) hook cave address (using hooklib)
    5) change SSDT value
    */

    static ULONG CodeSize = 0;
    static PVOID CodeStart = 0;
    if(!CodeStart)
    {
        ULONG_PTR Lowest = SSDTbase;
        ULONG_PTR Highest = Lowest + 0x0FFFFFFF;
        Log("[TITANHIDE] Range: 0x%p-0x%p\r\n", Lowest, Highest);
        CodeSize = 0;
        CodeStart = PE::GetPageBase(Undocumented::GetKernelBase(), &CodeSize, (PVOID)((oldValue >> 4) + SSDTbase));
        if(!CodeStart || !CodeSize)
        {
            Log("[TITANHIDE] PeGetPageBase failed...\r\n");
            return 0;
        }
        Log("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\r\n", CodeStart, CodeSize);
        if((ULONG_PTR)CodeStart < Lowest)  //start of the page is out of range (impossible, but whatever)
        {
            CodeSize -= (ULONG)(Lowest - (ULONG_PTR)CodeStart);
            CodeStart = (PVOID)Lowest;
            Log("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\r\n", CodeStart, CodeSize);
        }
        Log("[TITANHIDE] Range: 0x%p-0x%p\r\n", CodeStart, (ULONG_PTR)CodeStart + CodeSize);
    }

    PVOID CaveAddress = FindCaveAddress(CodeStart, CodeSize, sizeof(HOOKOPCODES));
    if(!CaveAddress)
    {
        Log("[TITANHIDE] FindCaveAddress failed...\r\n");
        return 0;
    }
    Log("[TITANHIDE] CaveAddress: 0x%p\r\n", CaveAddress);

    hHook = Hooklib::Hook(CaveAddress, (void*)newfunc);
    if(!hHook)
        return 0;

    newValue = (LONG)((ULONG_PTR)CaveAddress - SSDTbase);
    newValue = (newValue << 4) | oldValue & 0xF;

    //update HOOK structure
    hHook->SSDTindex = FunctionIndex;
    hHook->SSDTold = oldValue;
    hHook->SSDTnew = newValue;
    hHook->SSDTaddress = (oldValue >> 4) + SSDTbase;

#else
    /*
    x86 SSDT Hook:
    1) change SSDT value
    */
    newValue = (ULONG)newfunc;

    hHook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));

    //update HOOK structure
    hHook->SSDTindex = FunctionIndex;
    hHook->SSDTold = oldValue;
    hHook->SSDTnew = newValue;
    hHook->SSDTaddress = oldValue;

#endif

    RtlSuperCopyMemory(&SSDT->pServiceTable[FunctionIndex], &newValue, sizeof(newValue));

    Log("[TITANHIDE] SSDThook(%s:0x%p, 0x%p)\r\n", apiname, hHook->SSDTold, hHook->SSDTnew);

    return hHook;
}

void SSDT::Hook(HOOK hHook)
{
    if(!hHook)
        return;
    SSDTStruct* SSDT = SSDTfind();
    if(!SSDT)
    {
        Log("[TITANHIDE] SSDT not found...\r\n");
        return;
    }
    LONG* SSDT_Table = SSDT->pServiceTable;
    if(!SSDT_Table)
    {
        Log("[TITANHIDE] ServiceTable not found...\r\n");
        return;
    }
    RtlSuperCopyMemory(&SSDT_Table[hHook->SSDTindex], &hHook->SSDTnew, sizeof(hHook->SSDTnew));
}

void SSDT::Unhook(HOOK hHook, bool free)
{
    if(!hHook)
        return;
    SSDTStruct* SSDT = SSDTfind();
    if(!SSDT)
    {
        Log("[TITANHIDE] SSDT not found...\r\n");
        return;
    }
    LONG* SSDT_Table = SSDT->pServiceTable;
    if(!SSDT_Table)
    {
        Log("[TITANHIDE] ServiceTable not found...\r\n");
        return;
    }
    RtlSuperCopyMemory(&SSDT_Table[hHook->SSDTindex], &hHook->SSDTold, sizeof(hHook->SSDTold));
#ifdef _WIN64
    if(free)
        Hooklib::Unhook(hHook, true);
#else
    if(free)
        RtlFreeMemory(hHook);
#endif
}