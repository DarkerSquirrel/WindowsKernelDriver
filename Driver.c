
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>
#include <windowsx.h>

#define READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN , 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SET_PROCESS_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define TEST_IO_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN,0x904,METHOD_BUFFERED,FILE_SPECIAL_ACCESS) // Deneme için CTL KODU


PDEVICE_OBJECT DeviceOBJ;
UNICODE_STRING dev, dos;
PEPROCESS ApexProcess;
DWORD processID;

NTSTATUS DriverHandle(PDEVICE_OBJECT pDevice, PIRP irp);
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriver);
NTSTATUS ReadProcessMemory(PEPROCESS process, PVOID sourceAddr, PVOID destAddr, SIZE_T size);
NTSTATUS WriteProcessMemory(PEPROCESS process, PVOID sourceAddr, PVOID destAddr, SIZE_T size);

typedef struct _READ_MEMORY
{
	ULONG ProcessID;
	DWORD64 address;
	DWORD64 response;
	ULONG size;

} READ_MEMORY, *PREAD_MEMORY;

typedef struct _WRITE_MEMORY
{
	ULONG ProcessID;
	DWORD64 address;
	float value;
	ULONG size;

} WRITE_MEMORY, *PWRITE_MEMORY;

NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS  	SourceProcess,
	IN PVOID  	SourceAddress,
	IN PEPROCESS  	TargetProcess,
	OUT PVOID  	TargetAddress,
	IN SIZE_T  	BufferSize,
	IN KPROCESSOR_MODE  	PreviousMode,
	OUT PSIZE_T  	ReturnSize
);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	DbgPrintEx(0, 0, "Driver Loading\n");

	RtlInitUnicodeString(&dev, L"\\Device\\keepgoindriver");  //Stringi deðiþkenlere atadý.
	RtlInitUnicodeString(&dos, L"\\DosDevices\\keepgoindriver");

	IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, DeviceOBJ);
	IoCreateSymbolicLink(&dos, &dev);

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverHandle;
	DriverObject->DriverUnload = DriverUnload;

	DeviceOBJ->Flags |= DO_DIRECT_IO;
	DeviceOBJ->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

NTSTATUS DriverHandle(PDEVICE_OBJECT pDevice, PIRP irp) {
	NTSTATUS Status;
	ULONG IO_Bytes = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG Code = stack->Parameters.DeviceIoControl.IoControlCode;
	

	if (Code == READ_REQUEST) {
		PREAD_MEMORY READ_REQ = (PREAD_MEMORY)irp->AssociatedIrp.SystemBuffer;
		PEPROCESS process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(READ_REQ->ProcessID, &process)))
			ReadProcessMemory(process, READ_REQ->address, READ_REQ->response, READ_REQ->size);
		Status = STATUS_SUCCESS;
		IO_Bytes = sizeof(READ_MEMORY);
	}
	else if (Code == WRITE_REQUEST) {
		PWRITE_MEMORY WRITE_REQ = (PWRITE_MEMORY)irp->AssociatedIrp.SystemBuffer;
		PEPROCESS process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(WRITE_REQ->ProcessID, &process)))
			WriteProcessMemory(process, &WRITE_REQ->value, WRITE_REQ->address, WRITE_REQ->size);
		Status = STATUS_SUCCESS;
		IO_Bytes = sizeof(WRITE_MEMORY);
	}
	else if (Code == SET_PROCESS_REQUEST) {
		PULONG REQ_DATA = (PULONG)irp->AssociatedIrp.SystemBuffer;
		processID = *REQ_DATA;

		Status = STATUS_SUCCESS;
		IO_Bytes = sizeof(REQ_DATA);
	}
	else if (Code == GET_MODULE_REQUEST) {
		//Yapýlacak yer
	}
	else if (Code == TEST_IO_REQUEST) {

		PULONG TEST_DATA = (PULONG)irp->AssociatedIrp.SystemBuffer;
		Status = STATUS_SUCCESS;
		IO_Bytes = sizeof(TEST_DATA);
	}

	irp->IoStatus.Status = Status;
	irp->IoStatus.Information = IO_Bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

NTSTATUS ReadProcessMemory(PEPROCESS process,PVOID sourceAddr, PVOID destAddr, SIZE_T size) {
	PSIZE_T bytes;
	PEPROCESS SourceProcess = process;
	PEPROCESS DestProcess = PsGetCurrentProcess();
	__try
	{
		
		ProbeForRead(sourceAddr, size, (ULONG)size);
		if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, sourceAddr, DestProcess, destAddr, size, KernelMode, &bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS WriteProcessMemory(PEPROCESS process, PVOID sourceAddr, PVOID destAddr, SIZE_T size) {
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS DestProcess = process;
	PSIZE_T bytes;
	__try
	{
		ProbeForWrite(destAddr, size, (ULONG)size);
		if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, sourceAddr, DestProcess, destAddr, size, KernelMode, &bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriver) {
	DbgPrintEx(0, 0, "Driver Unloading\n");
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriver->DeviceObject);
}