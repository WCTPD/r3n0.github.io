---
layout: hgame2020 week1 wp
title: 第一个windows驱动
date: 2020-07-15 11:36:02
tags: windows
categories: 开发
---

# 第一个Windows驱动

### DriverEntry

`DriverEntry`是驱动的入口，相当于main函数



```C
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	driver->DriverUnload = unload; //unload的回调函数

	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("HHHHHEllo World\n");

	//创建设备
	
	UNICODE_STRING device_name = { 0 };

	PDEVICE_OBJECT pdevice = NULL;

	RtlInitUnicodeString(&device_name, DEVICE_NAME);

	status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, TRUE, &pdevice);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device Failed: %x\n", status);

		return status;
	}

	pdevice->Flags |= DO_BUFFERED_IO;//设置读写方式

	//设备创建成功 创建符号连接

	UNICODE_STRING symname = { 0 };

	RtlInitUnicodeString(&symname, SYMBOL_LINK_NAME);

	status = IoCreateSymbolicLink(&symname, &device_name);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateSymbolicLink Failed: %x\n", status);

		IoDeleteDevice(pdevice);

		return status;
	} 
	//回调函数，通过这些函数来与R3层进行交互
	driver->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	driver->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    driver->MajorFunction[IRP_MJ_CLEANUP] = DeviceCleanup;
	driver->MajorFunction[IRP_MJ_READ] = DeviceRead;
	driver->MajorFunction[IRP_MJ_WRITE] = DeviceWrite;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	return 0;
}
```

### unload

在驱动卸载的时候被调用，进行一些收尾清理

```C
VOID unload(PDRIVER_OBJECT pdriver)
{
	
	DbgPrint("Hello World\n");
	
	if (pdriver->DeviceObject)
	{
		IoDeleteDevice(pdriver->DeviceObject);

		UNICODE_STRING sym = { 0 };

		RtlInitUnicodeString(&sym, SYMBOL_LINK_NAME);

		IoDeleteSymbolicLink(&sym);
	}
	
}
```

### DeviceCreate

当R3层执行`CreateFile`函数时被调用

```C
NTSTATUS DeviceCreate(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been opened\n");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
```

### DeviceClose 和 DeviceCleanup

暂时不知道这两个具体的区别，当R3层执行`CloseHandle`时两个都会执行，并且DeviceCleanup在前

```C
NTSTATUS DeviceClose(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been closed");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceCleanup(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been cleaned up");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

```



### DeviceRead

通过缓冲区的方式进行读写

```C
NTSTATUS DeviceRead(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been readed");

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG readsize = pstack->Parameters.Read.Length;

	PCHAR readbuffer = pirp->AssociatedIrp.SystemBuffer;//与R3层的readbuffer指向同一空间

	RtlCopyMemory(readbuffer, "message from kernel", strlen("message from kernel"));

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = strlen("message from kernel");

	DbgPrint("read info len is %d", strlen("message from kernel"));

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
```

### DeviceWrite

```C
NTSTATUS DeviceWrite(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	//DbgPrint("This device has been cleaned up");

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG writesize = pstack->Parameters.Write.Length;

	PCHAR writebuffer = pirp->AssociatedIrp.SystemBuffer;

	pdevice->DeviceExtension = (PVOID)ExAllocatePool(NonPagedPool, 200);//申请空间

	RtlZeroMemory(pdevice->DeviceExtension, 200);//置零

	RtlCopyMemory(pdevice->DeviceExtension, writebuffer, writesize);

	DbgPrint("writebuffer's address is %p\n", writebuffer);

	DbgPrint("content: %s\n", (PCHAR)pdevice->DeviceExtension);

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 30;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
```

### DeviceControl

```C
NTSTATUS DeviceControl(PDEVICE_OBJECT pdevice, PIRP pirp) //自定义控制
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG iocode = pstack->Parameters.DeviceIoControl.IoControlCode; //接受功能号

	ULONG input_len = pstack->Parameters.DeviceIoControl.InputBufferLength;

	ULONG output_len = pstack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (iocode)
	{
	case IOCTL:
	{
		DWORD32 data = *(DWORD32*)pirp->AssociatedIrp.SystemBuffer;
		DbgPrint("input: %d", data);
		data *= 10;
		*(DWORD32*)pirp->AssociatedIrp.SystemBuffer = data;
		break;
	}
	default:
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 4;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
```



### 完整代码

```C
#include <ntifs.h>

#define DEVICE_NAME L"\\Device\\FirstDevice"
#define SYMBOL_LINK_NAME L"\\??\\FirstDevice1"
#define IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
DRIVER_INITIALIZE DriverEntry;
//EVT_WDF_DRIVER_DEVICE_ADD KmdfHelloWorldEvtDeviceAdd;


VOID unload(PDRIVER_OBJECT pdriver)
{
	
	DbgPrint("Hello World\n");
	
	if (pdriver->DeviceObject)
	{
		IoDeleteDevice(pdriver->DeviceObject);

		UNICODE_STRING sym = { 0 };

		RtlInitUnicodeString(&sym, SYMBOL_LINK_NAME);

		IoDeleteSymbolicLink(&sym);
	}
	
}

NTSTATUS DeviceCreate(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been opened\n");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been closed");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceCleanup(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been cleaned up");

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 0;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceRead(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("This device has been readed");

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG readsize = pstack->Parameters.Read.Length;

	PCHAR readbuffer = pirp->AssociatedIrp.SystemBuffer;//与R3层的readbuffer指向同一空间

	RtlCopyMemory(readbuffer, "message from kernel", strlen("message from kernel"));

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = strlen("message from kernel");

	DbgPrint("read info len is %d", strlen("message from kernel"));

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceWrite(PDEVICE_OBJECT pdevice, PIRP pirp)
{
	NTSTATUS status = STATUS_SUCCESS;

	//DbgPrint("This device has been cleaned up");

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG writesize = pstack->Parameters.Write.Length;

	PCHAR writebuffer = pirp->AssociatedIrp.SystemBuffer;

	pdevice->DeviceExtension = (PVOID)ExAllocatePool(NonPagedPool, 200);

	RtlZeroMemory(pdevice->DeviceExtension, 200);

	RtlCopyMemory(pdevice->DeviceExtension, writebuffer, writesize);

	DbgPrint("writebuffer's address is %p\n", writebuffer);

	DbgPrint("content: %s\n", (PCHAR)pdevice->DeviceExtension);

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 30;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT pdevice, PIRP pirp) //自定义控制
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);

	ULONG iocode = pstack->Parameters.DeviceIoControl.IoControlCode; //接受功能号

	ULONG input_len = pstack->Parameters.DeviceIoControl.InputBufferLength;

	ULONG output_len = pstack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (iocode)
	{
	case IOCTL:
	{
		DWORD32 data = *(DWORD32*)pirp->AssociatedIrp.SystemBuffer;
		DbgPrint("input: %d", data);
		data *= 10;
		*(DWORD32*)pirp->AssociatedIrp.SystemBuffer = data;
		break;
	}
	default:
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	pirp->IoStatus.Status = status;

	pirp->IoStatus.Information = 4;

	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	driver->DriverUnload = unload;

	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("HHHHHEllo World\n");

	//创建设备
	
	UNICODE_STRING device_name = { 0 };

	PDEVICE_OBJECT pdevice = NULL;

	RtlInitUnicodeString(&device_name, DEVICE_NAME);

	status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, TRUE, &pdevice);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device Failed: %x\n", status);

		return status;
	}

	pdevice->Flags |= DO_BUFFERED_IO;//设置读写方式

	//设备创建成功 创建符号连接

	UNICODE_STRING symname = { 0 };

	RtlInitUnicodeString(&symname, SYMBOL_LINK_NAME);

	status = IoCreateSymbolicLink(&symname, &device_name);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateSymbolicLink Failed: %x\n", status);

		IoDeleteDevice(pdevice);

		return status;
	} 
	//DbgPrint("su");
	driver->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	driver->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	driver->MajorFunction[IRP_MJ_CLEANUP] = DeviceCleanup;
	driver->MajorFunction[IRP_MJ_READ] = DeviceRead;
	driver->MajorFunction[IRP_MJ_WRITE] = DeviceWrite;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	return 0;
}
```

### 应用层的代码

```C
#include <iostream>
#include <Windows.h>
#include <winioctl.h>

#define IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main()
{
    HANDLE hDevice = NULL;
    char readBuffer[50] = { 0 };//与R0层的readbuffer指向同一空间
    DWORD read_num = 0;
    hDevice = CreateFileW(L"\\\\.\\FirstDevice1", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Open device failed\n");
        system("pause");
        return 0;
    }
    printf("Open device success\n");
    system("pause");
    ReadFile(hDevice, (LPVOID)readBuffer, 30, &read_num, NULL);
    printf("读取的内容为:%s\n读取的字节数为%d\n", readBuffer, read_num);
    system("pause");
    WriteFile(hDevice, "message from r3", 200, &read_num, NULL);
    printf("writebuffer的地址为: %p\n", "message from r3");
    system("pause");
    DWORD i = 100, o = 0;
    DeviceIoControl(hDevice, IOCTL, &i, 4, &o, 4, &read_num, NULL);
    printf("res: %d", o);
    system("pause");
    CloseHandle(hDevice);
    system("pause");
    return 0;
}
```

> 参考资料
>
> https://www.bilibili.com/video/BV1QJ411A7kR?from=search&seid=16227263836294897181

