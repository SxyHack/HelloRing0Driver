
#include "DriverEntry.h"
#include "HookSSDT.h"
//
// Include files.
//
#include "infinityHook/infinityhook.h"


#define NT_DEVICE_NAME      L"\\Device\\FUCKGAMEEYE"
#define DOS_DEVICE_NAME     L"\\DosDevices\\FuckGameEye"

//
// Device driver routine declarations.
//
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)

EXTERN_C DRIVER_INITIALIZE DriverEntry;
EXTERN_C DRIVER_DISPATCH SioctlCreateClose;
EXTERN_C DRIVER_DISPATCH SioctlDeviceControl;
EXTERN_C DRIVER_UNLOAD SioctlUnloadDriver;

void PrintIRPInfo(PIRP irp);
void PrintChars(_In_reads_(CountChars) PCHAR bufferAddress, _In_ size_t CountChars);

//#ifdef ALLOC_PRAGMA
//#pragma alloc_text(INIT, DriverEntry)
//#pragma alloc_text(PAGE, SioctlCreateClose)
//#pragma alloc_text(PAGE, SioctlDeviceControl)
//#pragma alloc_text(PAGE, SioctlUnloadDriver)
//#pragma alloc_text(PAGE, PrintIRPInfo)
//#pragma alloc_text(PAGE, PrintChars)
//#endif // ALLOC_PRAGMA

PULONG64 lpFnNtOpenProcess = NULL; // 保存原始的函数地址
ULONG64  ulFunctionID = 0;

NTSTATUS NTAPI HK_NtOpenProcess(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId)
{
	UNREFERENCED_PARAMETER(processHandle);
	UNREFERENCED_PARAMETER(desiredAccess);
	UNREFERENCED_PARAMETER(objectAttributes);
	UNREFERENCED_PARAMETER(clientId);

	PEPROCESS process = 0;
	if (STATUS_SUCCESS == PsLookupProcessByProcessId(clientId->UniqueProcess, &process))
	{
		PCHAR szFileName = PsGetProcessImageFileName(process);
		if (strcmp(szFileName, "notepad.exe") == 0)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	//判断要打开的进程ID是不是我们要保护的进程
	//if (clientId->UniqueProcess == (HANDLE)76)
	//	return (NTSTATUS)STATUS_ACCESS_DENIED; // -1073741790;//返回“拒绝访问”错误
	//不是我们要保护的进程，定义一个函数指针 _NtOpenProcess ,根据 oldNtOpenProcess 记录的真实函数的地址进行 Call
	//也就是说其他进程直接交还给系统的 NtOpenProcess 处理
	return ((_NtOpenProcess)lpFnNtOpenProcess)(processHandle, desiredAccess, objectAttributes, clientId);
}

VOID HookSSDT()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	ver.dwOSVersionInfoSize = sizeof(ver);
	RtlGetVersion(&ver);

	ClosePageWriteProtect();
	PKESERVICE_DESCRIPTOR_TABLE pAddress = GetSSDTEntryPtr();
	kprintf("SSDT ADDR: 0X%08X\n", (ULONG64)pAddress);

	lpFnNtOpenProcess = (PULONG64)GetSSDTFunction("NtOpenProcess", &ulFunctionID);

	SetSSDTFunction(pAddress, ulFunctionID, (ULONG64)HK_NtOpenProcess);
	//pAddress->ServiceTableBase[ulFunctionID] = &HK_NtOpenProcess;
	kprintf("NtOpenProcess ADDR: 0X%08X\n", (ULONG64)lpFnNtOpenProcess);
	//LOG_INFO("test");
	ResetPageWriteProtect();
}

void UnHookSSDT()
{
	if (lpFnNtOpenProcess == NULL)
		return;
	if (ulFunctionID == 0)
		return;

	ClosePageWriteProtect();

	PKESERVICE_DESCRIPTOR_TABLE pAddress = GetSSDTEntryPtr();
	SetSSDTFunction(pAddress, ulFunctionID, (ULONG64)lpFnNtOpenProcess);

	ResetPageWriteProtect();
}

//
// 测试InfinityHook
//
_NtOpenProcess pfnOldNtOpenProcess = NULL;

void __fastcall SyscallStub(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	// Enabling this message gives you VERY verbose logging... and slows
	// down the system. Use it only for debugging.
#if 0
	kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!NtOpenProcess calls.
	//
	if (*SystemCallFunction == pfnOldNtOpenProcess)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		*SystemCallFunction = (PVOID)HK_NtOpenProcess;
	}

}

void Hook2()
{
	UNICODE_STRING usFuncName = RTL_CONSTANT_STRING(L"NtOpenProcess");
	kprintf("[+] infinityhook: Loaded.\n");
	pfnOldNtOpenProcess = (_NtOpenProcess)MmGetSystemRoutineAddress(&usFuncName);
	if (pfnOldNtOpenProcess == NULL) {
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", usFuncName);
		return;
	}

	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS        ntStatus;
	UNICODE_STRING  strDeviceName;          // NT Device Name "\Device\SIOCTL"
	UNICODE_STRING  strWin32DevName;        // Win32 Name "\DosDevices\IoctlTest"
	PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

	UNREFERENCED_PARAMETER(RegistryPath);
	RtlInitUnicodeString(&strDeviceName, NT_DEVICE_NAME);
	ntStatus = IoCreateDevice(DriverObject,
		0,
		&strDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&deviceObject);

	if (!NT_SUCCESS(ntStatus)) {
		kprintf("Couldn't create the device object\n");
		return ntStatus;
	}

	//
	// Initialize the driver object with this driver's entry points.
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
	DriverObject->DriverUnload = SioctlUnloadDriver;


	//
	// Initialize a Unicode String containing the Win32 name
	// for our device.
	//
	RtlInitUnicodeString(&strWin32DevName, DOS_DEVICE_NAME);

	// Create a symbolic link between our device name and the Win32 name
	ntStatus = IoCreateSymbolicLink(&strWin32DevName, &strDeviceName);

	if (!NT_SUCCESS(ntStatus))
	{
		//
		// Delete everything that this routine has allocated.
		//
		kprintf("Couldn't create symbolic link\n");
		IoDeleteDevice(deviceObject);
	}

	kprintf("Driver Starting...\n");

	return ntStatus;
}

NTSTATUS SioctlCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID SioctlUnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;

	PAGED_CODE();

	//
	// Create counted string version of our Win32 device name.
	//
	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);

	//
	// Delete the link from our device name to a name in the Win32 namespace.
	//
	IoDeleteSymbolicLink(&uniWin32NameString);

	if (deviceObject != NULL)
	{
		IoDeleteDevice(deviceObject);
	}

	UnHookSSDT();
	IfhRelease();
}


/*++
Routine Description:
	This routine is called by the I/O system to perform a device I/O
	control function.

Arguments:
	DeviceObject - a pointer to the object that represents the device that I/O is to be done on.
	Irp - a pointer to the I/O Request Packet for this request.

Return Value:
	NT status code
--*/
NTSTATUS SioctlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PCHAR               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               data = "This String is from Device Driver !!!";
	size_t              datalen = strlen(data) + 1;//Length of data including null
	//PMDL                mdl = NULL;
	//PCHAR               buffer = NULL;

	PAGED_CODE();
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;



	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_FGE_HOOK_SSDT:
		kprintf("Called IOCTL_FGE_HOOK_SSDT\n");
		if (!inBufLength || !outBufLength)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto End;
		}
		inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		outBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		kprintf("\tData from User :");
		PrintChars(inBuf, inBufLength);
		RtlCopyBytes(outBuf, data, outBufLength);
		kprintf("\tData to User : ");
		PrintChars(outBuf, datalen);
		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		HookSSDT();
		break;
	case IOCTL_FGE_HOOK_INF:
		Hook2();
		break;
	default:
		//
		// The specified I/O control code is unrecognized by this driver.
		//
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		kprintf("ERROR: unrecognized IOCTL %x\n",
			irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

End:
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

void PrintIRPInfo(PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	kprintf("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer);
	kprintf("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	kprintf("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	kprintf("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	kprintf("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
}

void PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars)
{
	PAGED_CODE();
	if (CountChars) {
		while (CountChars--) {
			if (*BufferAddress > 31
				&& *BufferAddress != 127) {
				KdPrint(("%c", *BufferAddress));
			}
			else {
				KdPrint(("."));
			}
			BufferAddress++;
		}
		KdPrint(("\n"));
	}
}

