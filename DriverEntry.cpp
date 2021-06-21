
#include "DriverEntry.h"
//#include "HookSSDT.h"
#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "log.h"
#include "ntdll.h"
#include "threadhidefromdbg.h"

//
// Include files.
//

#define NT_DEVICE_NAME      L"\\Device\\FuckGameEye"
#define DOS_DEVICE_NAME     L"\\DosDevices\\FuckGameEye"

//
// Device driver routine declarations.
//
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)

EXTERN_C DRIVER_INITIALIZE DriverEntry;
EXTERN_C DRIVER_DISPATCH   EasyHideCreateClose;
EXTERN_C DRIVER_DISPATCH   EasyHideDeviceControl;
EXTERN_C DRIVER_UNLOAD     EasyHideUnloadDriver;

void PrintIRPInfo(PIRP irp);
void PrintChars(_In_reads_(CountChars) PCHAR bufferAddress, _In_ size_t CountChars);


PULONG64 lpFnNtOpenProcess = NULL; // 保存原始的函数地址
ULONG64  ulFunctionID = 0;

//NTSTATUS NTAPI HK_NtOpenProcess(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId)
//{
//	UNREFERENCED_PARAMETER(processHandle);
//	UNREFERENCED_PARAMETER(desiredAccess);
//	UNREFERENCED_PARAMETER(objectAttributes);
//	UNREFERENCED_PARAMETER(clientId);
//
//	PEPROCESS process = 0;
//	if (STATUS_SUCCESS == PsLookupProcessByProcessId(clientId->UniqueProcess, &process))
//	{
//		PCHAR szFileName = PsGetProcessImageFileName(process);
//		if (strcmp(szFileName, "notepad.exe") == 0)
//		{
//			return STATUS_ACCESS_DENIED;
//		}
//	}
//
//	//判断要打开的进程ID是不是我们要保护的进程
//	//if (clientId->UniqueProcess == (HANDLE)76)
//	//	return (NTSTATUS)STATUS_ACCESS_DENIED; // -1073741790;//返回“拒绝访问”错误
//	//不是我们要保护的进程，定义一个函数指针 _NtOpenProcess ,根据 oldNtOpenProcess 记录的真实函数的地址进行 Call
//	//也就是说其他进程直接交还给系统的 NtOpenProcess 处理
//	return ((_NtOpenProcess)lpFnNtOpenProcess)(processHandle, desiredAccess, objectAttributes, clientId);
//}
//
//VOID HookSSDT()
//{
//	RTL_OSVERSIONINFOW ver = { 0 };
//	ver.dwOSVersionInfoSize = sizeof(ver);
//	RtlGetVersion(&ver);
//
//	ClosePageWriteProtect();
//	PKESERVICE_DESCRIPTOR_TABLE pAddress = GetSSDTEntryPtr();
//	kprintf("SSDT ADDR: 0X%08X\n", (ULONG64)pAddress);
//
//	lpFnNtOpenProcess = (PULONG64)GetSSDTFunction("NtOpenProcess", &ulFunctionID);
//
//	SetSSDTFunction(pAddress, ulFunctionID, (ULONG64)HK_NtOpenProcess);
//	//pAddress->ServiceTableBase[ulFunctionID] = &HK_NtOpenProcess;
//	kprintf("NtOpenProcess ADDR: 0X%08X\n", (ULONG64)lpFnNtOpenProcess);
//	//LOG_INFO("test");
//	ResetPageWriteProtect();
//}
//
//void UnHookSSDT()
//{
//	if (lpFnNtOpenProcess == NULL)
//		return;
//	if (ulFunctionID == 0)
//		return;
//
//	ClosePageWriteProtect();
//
//	PKESERVICE_DESCRIPTOR_TABLE pAddress = GetSSDTEntryPtr();
//	SetSSDTFunction(pAddress, ulFunctionID, (ULONG64)lpFnNtOpenProcess);
//
//	ResetPageWriteProtect();
//}
//
//


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
NTSTATUS EasyHideDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PCHAR               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               data = "This String is from Device Driver !!!";
	size_t              datalen = strlen(data) + 1;//Length of data including null

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;



	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_FGE_HIDE:
		Log("Called IOCTL_FGE_HIDE\n");
		//if (!inBufLength || !outBufLength)
		//{
		//	ntStatus = STATUS_INVALID_PARAMETER;
		//	goto End;
		//}
		inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		outBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		Log("\tData from User :");
		PrintChars(inBuf, inBufLength);
		RtlCopyBytes(outBuf, data, outBufLength);
		Log("\tData to User : ");
		PrintChars(outBuf, datalen);
		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		//if (Hider::ProcessData(inBuf, inBufLength))
		//{
		//	Log("[TITANHIDE] HiderProcessData OK!\r\n");
		//}
		//else
		//{
		//	Log("[TITANHIDE] HiderProcessData failed...\r\n");
		//	ntStatus = STATUS_UNSUCCESSFUL;
		//}

		break;
	case IOCTL_FGE_HOOK_INF:
		break;
	default:
		//
		// The specified I/O control code is unrecognized by this driver.
		//
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		Log("ERROR: unrecognized IOCTL %x\n", irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
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
		Log("Couldn't create the device object\n");
		return ntStatus;
	}

	//
	// Initialize the driver object with this driver's entry points.
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = EasyHideCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = EasyHideCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EasyHideDeviceControl;
	DriverObject->DriverUnload = EasyHideUnloadDriver;


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
		Log("Couldn't create symbolic link\n");
		IoDeleteDevice(deviceObject);
	}

	Log("Driver Starting...\n");

	return ntStatus;
}

NTSTATUS EasyHideCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID EasyHideUnloadDriver(IN PDRIVER_OBJECT DriverObject)
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

	//UnHookSSDT();
	Hooks::Deinitialize();
	NTDLL::Deinitialize();
}



void PrintIRPInfo(PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	Log("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer);
	Log("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	Log("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	Log("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	Log("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
}

void PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars)
{
	PAGED_CODE();
	if (CountChars) {
		while (CountChars--) {
			if (*BufferAddress > 31
				&& *BufferAddress != 127) {
				Log("%c", *BufferAddress);
			}
			else {
				Log(("."));
			}
			BufferAddress++;
		}
		Log(("\n"));
	}
}

