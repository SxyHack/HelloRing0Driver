
#include "DriverEntry.h"
#include "hookSSDT.h"
//
// Include files.
//

#include "DriverEntry.h"
#include "hookSSDT.h"

#define NT_DEVICE_NAME      L"\\Device\\FUCKGAMEEYE"
#define DOS_DEVICE_NAME     L"\\DosDevices\\FuckGameEye"

#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("FUCKGAMEEYE.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif


//
// Device driver routine declarations.
//
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)

DRIVER_INITIALIZE DriverEntry;
DRIVER_DISPATCH SioctlCreateClose;
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;


void PrintIRPInfo(PIRP irp);
void PrintChars(_In_reads_(CountChars) PCHAR bufferAddress, _In_ size_t CountChars);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SioctlCreateClose)
#pragma alloc_text(PAGE, SioctlDeviceControl)
#pragma alloc_text(PAGE, SioctlUnloadDriver)
#pragma alloc_text(PAGE, PrintIRPInfo)
#pragma alloc_text(PAGE, PrintChars)
#endif // ALLOC_PRAGMA

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
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
		SIOCTL_KDPRINT(("Couldn't create the device object\n"));
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
		SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
		IoDeleteDevice(deviceObject);
	}

	SIOCTL_KDPRINT(("Driver Starting...\n"));

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
}

PULONG64 lpFnNtOpenProcess = NULL; // ����ԭʼ�ĺ�����ַ

NTSTATUS NTAPI HK_NtOpenProcess(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId)
{
	UNREFERENCED_PARAMETER(processHandle);
	UNREFERENCED_PARAMETER(desiredAccess);
	UNREFERENCED_PARAMETER(objectAttributes);
	UNREFERENCED_PARAMETER(clientId);

	PEPROCESS process = 0;
	if (STATUS_SUCCESS == PsLookupProcessByProcessId(clientId->UniqueProcess, &process))
	{
		if (strcmp(PsGetProcessImageFileName(process), "notepad.exe") == 0)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	//�ж�Ҫ�򿪵Ľ���ID�ǲ�������Ҫ�����Ľ���
	//if (clientId->UniqueProcess == (HANDLE)76)
	//	return (NTSTATUS)STATUS_ACCESS_DENIED; // -1073741790;//���ء��ܾ����ʡ�����
	//��������Ҫ�����Ľ��̣�����һ������ָ�� _NtOpenProcess ,���� oldNtOpenProcess ��¼����ʵ�����ĵ�ַ���� Call
	//Ҳ����˵��������ֱ�ӽ�����ϵͳ�� NtOpenProcess ����
	return ((_NtOpenProcess)lpFnNtOpenProcess)(processHandle, desiredAccess, objectAttributes, clientId);
}

VOID DoHookSsdt()
{
	ULONG64 ulFunctionID = 0;
	RTL_OSVERSIONINFOW ver = { 0 };
	ver.dwOSVersionInfoSize = sizeof(ver);
	RtlGetVersion(&ver);

	ClosePageWriteProtect();
	PKESERVICE_DESCRIPTOR_TABLE pAddress = GetSSDTEntryPtr();
	SIOCTL_KDPRINT(("SSDT ADDR: 0X%08X in METHOD_NEITHER\n", pAddress));

	lpFnNtOpenProcess = GetSSDTFunction("NtOpenProcess", &ulFunctionID);

	SetSSDTFunction(pAddress, ulFunctionID, (ULONG64)HK_NtOpenProcess);
	//pAddress->ServiceTableBase[ulFunctionID] = &HK_NtOpenProcess;
	SIOCTL_KDPRINT(("NtOpenProcess ADDR: 0X%08X\n", lpFnNtOpenProcess));

	ResetPageWriteProtect();
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

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SIOCTL_METHOD_BUFFERED:
		SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_BUFFERED\n"));
		PrintIRPInfo(Irp);
		inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		outBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		SIOCTL_KDPRINT(("\tData from User :"));
		PrintChars(inBuf, inBufLength);
		RtlCopyBytes(outBuf, data, outBufLength);

		SIOCTL_KDPRINT(("\tData to User : "));
		PrintChars(outBuf, datalen);
		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		DoHookSsdt();
		break;
	//case IOCTL_SIOCTL_METHOD_IN_DIRECT:
	//	SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_IN_DIRECT\n"));
	//	PrintIRPInfo(Irp);
	//	inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
	//	SIOCTL_KDPRINT(("\tData from User in InputBuffer: "));
	//	PrintChars(inBuf, inBufLength);
	//	buffer = (PCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
	//	if (!buffer) {
	//		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	//		break;
	//	}
	//	SIOCTL_KDPRINT(("\tData from User in OutputBuffer: "));
	//	PrintChars(buffer, outBufLength);
	//	Irp->IoStatus.Information = MmGetMdlByteCount(Irp->MdlAddress);
	//	break;
	//case IOCTL_SIOCTL_METHOD_OUT_DIRECT:
	//	SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_OUT_DIRECT\n"));
	//	PrintIRPInfo(Irp);
	//	inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
	//	SIOCTL_KDPRINT(("\tData from User : "));
	//	PrintChars(inBuf, inBufLength);
	//	buffer = (PCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
	//	if (!buffer) {
	//		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	//		break;
	//	}
	//	RtlCopyBytes(buffer, data, outBufLength);
	//	SIOCTL_KDPRINT(("\tData to User : "));
	//	PrintChars(buffer, datalen);
	//	Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);
	//	break;
	default:

		//
		// The specified I/O control code is unrecognized by this driver.
		//
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
			irpSp->Parameters.DeviceIoControl.IoControlCode));
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

	SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer));
	SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
	SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
	SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength));
	SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength));
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

