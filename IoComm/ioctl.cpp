#include "ioctl.h"
#include "kernel.h"
#include "mm.h"
#include "pml4.h"
#include "file.h"
#include "inject.h"
#include <ntstrsafe.h>
#include <ntimage.h>

#define DRIVER_NAME L"\\Driver\\Null"
#define DEVICE_NAME L"\\Device\\Null"
//#define SYSMLINK_NAME	L"\\??\\DefenseDDK"
#define SYSFILE_PATH	L"\\??\\C:\\Windows\\System32\\drivers\\null.sys"
#define DLLFILE_PATH	L"\\??\\C:\\Windows\\System32\\ntdll.dll"

extern "C"
{
	extern POBJECT_TYPE *IoDriverObjectType;

	PDRIVER_DISPATCH OriDriverDeviceControl = NULL;
	PIOCTLCALLBACK IoctlIoCallBack = NULL;	
	/*
			push rsp
			push rbx
			mov ebx,0x12345678
			mov eax,0x78563412
			shl rax,0x20
			or rax,rbx
			sub rsp,0x30
			call rax
			add rsp,0x30
			pop rbx
			pop rsp
			ret
		*/
	CHAR CallRaxShellCodeWin7[32] = { 0x55,0x53,0xBB,0x78,0x56,0x34,0x12,0xB8,0x12,0x34,0x56,0x78,0x48,0xC1,0xE0,0x20,0x48,0x0B,0xC3,0x48,0x83,0xEC,0x30,0xFF,0xD0,0x48,0x83,0xC4,0x30,0x5B,0x5D,0xC3 };
	/*
		push 0x12345678
		mov dword ptr ss:[rsp+0x4],0x78563412
		ret
	*/
	CHAR CallRaxShellCodeWin10[14] = {0x68,0x78,0x56,0x34,0x12,0xC7,0x44,0x24,0x04,0x12,0x34,0x56,0x78,0xC3};
	//CHAR,CallRaxShellCode[34] = {0x55,0x56,0x57,0x48,0x83,0xEC,0x28,0xBE,0x78,0x56,0x34,0x12,0xB8,0x12,0x34,0x56,0x78,0x48,0xC1,0xE0,0x20,0x48,0x0B,0xC6,0xFF,0xD0,0x48,0x83,0xC4,0x28,0x5F,0x5E,0x5D,0xC3};
	bool isInitOk = false;
	bool isRegistryOk = false;
	PDRIVER_OBJECT HookDriverObejct = NULL;
	PUNICODE_STRING HookSymLinkName = NULL;

	_Use_decl_annotations_
		void Ioctl::IoctlInit()
	{
		if (!isInitOk) {
			Pml4::Pml4Init();
			Inject::InitInject();
			isInitOk = true;
		}
	}

	_Use_decl_annotations_
		bool Ioctl::RegistryIoctlCallBack(IN PIOCTLCALLBACK IoCallBack)
	{	
		/*
			初始化要用到的符号
		*/

		if (IoCallBack && !IoctlIoCallBack) {		
			IoctlIoCallBack = IoCallBack;		
			if (!isRegistryOk)
				if (!DriverInterceptIoComm())
					return false;

			return (isRegistryOk = true);
		}
		else
			return false;
	}

	_Use_decl_annotations_
		void Ioctl::UnRegistryIoctlCallBack()
	{
		if (IoctlIoCallBack && OriDriverDeviceControl)
		{
			IoctlIoCallBack = NULL;
			isRegistryOk = false;
			HookDriverObejct->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriDriverDeviceControl;
			// 删除符号链接
			if (HookSymLinkName) {
				IoDeleteSymbolicLink(HookSymLinkName);
				ObDereferenceObject(HookDriverObejct);
			}
		}
	}
	
	_Use_decl_annotations_
		bool Ioctl::DriverInterceptIoComm(IN wchar_t* DriverSymbolicLink)
	{
		/*
			1. 获取目标驱动对象, 并随机创建符号链接
		*/
		// 获取指定的驱动对象
		NTSTATUS NtStatus = STATUS_SUCCESS;
		UNICODE_STRING DriverName = RTL_CONSTANT_STRING(DRIVER_NAME);
		PDRIVER_OBJECT DriverObject;
	
		NtStatus = ObReferenceObjectByName(&DriverName,
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, FILE_ANY_ACCESS,
					*IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);
		if (!NT_SUCCESS(NtStatus))
		{
			KdPrint(("获取驱动对象出错%x\n", NtStatus));
			return false;
		}
		else
			HookDriverObejct = DriverObject;

		// 寻找设备对象
		bool isCreate = false;
		UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
		PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
		if (!DeviceObject) {
			// 没有创建一个设备对象
			NtStatus = IoCreateDevice(DriverObject,
				0,
				&DeviceName,
				FILE_DEVICE_UNKNOWN,
				FILE_DEVICE_SECURE_OPEN,
				FALSE,
				&DeviceObject);
			if (NT_SUCCESS(NtStatus) != STATUS_SUCCESS) {
				KdPrint(("设备设备对象失败: %x!\n", NtStatus));
				return false;
			}
			isCreate = true;
		}

		// 创建随机符号链接
		PUNICODE_STRING pSysmbolicLinkName = GetSymRandName();
		//UNICODE_STRING SysmbolicLinkName = RTL_CONSTANT_STRING(SYSMLINK_NAME);
		NtStatus = IoCreateSymbolicLink(pSysmbolicLinkName, &DeviceName);
		if (!NT_SUCCESS(NtStatus))
		{
			KdPrint(("设备符号链接失败!\n"));
			if (isCreate)
				IoDeleteDevice(DeviceObject);
			if (pSysmbolicLinkName->Buffer)
				ExFreePoolWithTag(pSysmbolicLinkName, 'istr');
			return false;
		}
		else { 
			HookSymLinkName = pSysmbolicLinkName;
			KdPrint(("设备符号链接成功!\n")); 
		}
		/*
			2. 拦截目标 IRP_MJ_DEVICE_CONTROL 处理函数
		*/
		CHAR* CallRaxShellCode = NULL;
		ULONG CallRaxShellCodeSize = 0;
		if (Pml4::GetWindowsVersion() == WIN10)		{
			CallRaxShellCode = CallRaxShellCodeWin10;
			CallRaxShellCodeSize = sizeof(CallRaxShellCodeWin10);
		}
		else if (Pml4::GetWindowsVersion() == WIN7){
			CallRaxShellCode = CallRaxShellCodeWin7;
			CallRaxShellCodeSize = sizeof(CallRaxShellCodeWin7);
		}
		else return false;

		// 寻找目标模块空白处
		uintptr_t MoudleMemCodeAddress = Mm::get_free_speace((uintptr_t)DriverObject->DriverStart, DriverObject->DriverSize, CallRaxShellCodeSize);
		if (!MoudleMemCodeAddress) {
			KdPrintEx((77, 0, "寻找目标模块空白处失败\n"));
			return false;
		}
		// 写入Hook函数地址
		for (int i = 0; i < CallRaxShellCodeSize; i++)
		{
			auto write_ptr = (ULONG32*)((PUCHAR)CallRaxShellCode + i);
			auto write_ptr64 = (ULONG64*)((PUCHAR)CallRaxShellCode + i);
			if (*write_ptr == 0x12345678) {
				*write_ptr = (ULONG32)((ULONG64)DrvIoControlHandler & 0xFFFFFFFF);
			}
			if (*write_ptr == 0x78563412) {
				*write_ptr = (ULONG32)(((ULONG64)DrvIoControlHandler >> 32) & 0xFFFFFFFF);
			}
		}
		// 考入ShellCode
		Mm::_memcpy((PVOID)MoudleMemCodeAddress, CallRaxShellCode, CallRaxShellCodeSize);
		// 保存原 IRP_MJ_DEVICE_CONTROL 处理函数地址
		OriDriverDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		// 拦截 IRP_MJ_DEVICE_CONTROL	
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)MoudleMemCodeAddress;

		/*
			3. 将随机符号链接写入NTDLL PE结构中, 用于R3通信
		*/
		SymLinkNameWriteNtdll(pSysmbolicLinkName);

		/*
			4. 保护文件不被打开，防止文件比对校验
		*/
		if (!File::LockFile(DLLFILE_PATH) || !File::LockFile(SYSFILE_PATH)) {
			KdPrintEx((77, 0, "LockFile失败 \n"));
			//return false;
		}

		/*
			5. 当前驱动隐藏
		*/

		return true;
	}

	_Use_decl_annotations_
		PUNICODE_STRING Ioctl::GetSymRandName()
	{
		static PUNICODE_STRING uName = NULL;
		if (uName) return uName;

		LARGE_INTEGER CurrentTime = {};
		KeQuerySystemTime(&CurrentTime);

		ULONG randNumber1 = RtlRandomEx(&CurrentTime.LowPart);
		ULONG randNumber2 = RtlRandomEx(&CurrentTime.LowPart);
		
		wchar_t * buffer_name = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, (sizeof(wchar_t) + 1) * 100, 'istr');
		RtlZeroMemory(buffer_name, (sizeof(wchar_t) + 1) * 100);
		RtlStringCbPrintfW(buffer_name, 100 * sizeof(wchar_t), L"\\??\\%x%x", randNumber1, randNumber2);

		uName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'istr');
		uName->Length = wcslen(buffer_name) * 2;
		uName->Buffer = buffer_name;
		uName->MaximumLength = uName->Length + 2;

		return uName;
	}

	_Use_decl_annotations_
		bool Ioctl::SymLinkNameWriteNtdll(PUNICODE_STRING SysmbolicLinkName)
	{

		// 遍历 explorer.exe 进程获取NTDLL模块信息
		// 1. 获取 explorer.exe 内核进程结构体
		PEPROCESS Process = GetProcessObjectByName(L"explorer.exe");
		if (!Process)	return false;

		// 2. 附加进程向NTDLL写入信息
		KAPC_STATE ApcState = {};
		KeStackAttachProcess(Process, &ApcState);

		PPEB ProcessPeb = PsGetProcessPeb(Process);
		if (ProcessPeb == NULL)
			return false;

		//PEB + 0x18 = PEB.Ldr
		auto peb_ldr = *(PDWORD64)((PUCHAR)ProcessPeb + 0x18);
		//Pebldr + 0x10 = InLoadOrderModuleList
		PLIST_ENTRY module_list_head = (PLIST_ENTRY)((PUCHAR)peb_ldr + 0x10);
		PLIST_ENTRY moudle = module_list_head->Flink;
		PLDR_DATA_TABLE_ENTRY info = NULL;
		UNICODE_STRING	str_moudle_name = {};
		RtlInitUnicodeString(&str_moudle_name, L"ntdll.dll");

		while (module_list_head != moudle) // 判断是否到达开头
		{
			info = (PLDR_DATA_TABLE_ENTRY)moudle;

			if (RtlCompareUnicodeString(
				&str_moudle_name,
				&info->BaseDllName,
				true
			) == 0)
			{
				// 如果为NTDLL, 向其写入数据
				PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(info->DllBase);
				Mm::_memcpy((UCHAR*)&DosHeader->e_lfanew + sizeof(LONG), SysmbolicLinkName->Buffer, SysmbolicLinkName->Length + sizeof(WCHAR));
				break;
			}

			moudle = moudle->Flink; // 继续向下遍历
		}
		
		KeUnstackDetachProcess(&ApcState);

		return true;
	}

	_Use_decl_annotations_
		PEPROCESS Ioctl::GetProcessObjectByName(wchar_t* wProcessName)
	{
		NTSTATUS NtStstus = STATUS_UNSUCCESSFUL;
		PEPROCESS Process = NULL;
		PUNICODE_STRING uProcessName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'istr');

		for (ULONG PricessId = 4; PricessId < 20000; PricessId += 4)
		{
			NtStstus = PsLookupProcessByProcessId((HANDLE)PricessId, &Process);
			if (NT_SUCCESS(NtStstus))
			{
				// 获取进程名称
				NtStstus = SeLocateProcessImageName(Process, &uProcessName);
				if (NT_SUCCESS(NtStstus))
				{
					if (!MmIsAddressValid(uProcessName->Buffer) && !uProcessName->Length)
						continue;

					if (wcsstr(uProcessName->Buffer, wProcessName) != 0) {
						// 如果为目标进程返回
						ExFreePoolWithTag(uProcessName, 'istr');
						return Process;
					}
				}
			}
		}

		ExFreePoolWithTag(uProcessName, 'istr');
		return NULL;
	}

	_Use_decl_annotations_
		NTSTATUS Ioctl::DrvIoControlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
	{
		UNREFERENCED_PARAMETER(DeviceObject);
		PCHAR InputBuffer = NULL;
		ULONG InputLength = 0;
		PCHAR OutputBuffer = NULL;
		ULONG OutputLength = 0;
		ULONG Length = 0;
		NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
		PIO_STACK_LOCATION sTack = IoGetCurrentIrpStackLocation(Irp);
		// 获取 IO功能码
		ULONG IoCode = sTack->Parameters.DeviceIoControl.IoControlCode;
		
		switch (IoCode)
		{
		case CTL_IO_COMM:
		{
			// 获取输入缓冲区的地址
			PIO_COMM_CODE pIoCommCode = (PIO_COMM_CODE)Irp->AssociatedIrp.SystemBuffer;
			// 获取输入缓冲区的长度
			InputLength = (ULONG)sTack->Parameters.DeviceIoControl.InputBufferLength;
			
			if (InputLength && MmIsAddressValid(pIoCommCode)) {

				// 调用IoCallBack
				if (IoctlIoCallBack) {
					Irp->IoStatus.Status = IoctlIoCallBack(pIoCommCode);
				}
				
			}
		}break;
		default:
			break;
		}
		
		if (NT_SUCCESS(Irp->IoStatus.Status))
		{
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}

		return OriDriverDeviceControl(DeviceObject, Irp);
	}

	_Use_decl_annotations_
		NTSTATUS Ioctl::DrvDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
	{
		UNREFERENCED_PARAMETER(DeviceObject);
		static CHAR * iRpName[] = {
		"IRP_MJ_CREATE                                          ",
		"IRP_MJ_CREATE_NAMED_PIPE                 ",
		"IRP_MJ_CLOSE                                    ",
		"IRP_MJ_READ                                     ",
		"IRP_MJ_WRITE                                    ",
		"IRP_MJ_QUERY_INFORMATION                 ",
		"IRP_MJ_SET_INFORMATION                          ",
		"IRP_MJ_QUERY_EA                                 ",
		"IRP_MJ_SET_EA                                          ",
		"IRP_MJ_FLUSH_BUFFERS                            ",
		"IRP_MJ_QUERY_VOLUME_INFORMATION   ",
		"IRP_MJ_SET_VOLUME_INFORMATION            ",
		"IRP_MJ_DIRECTORY_CONTROL                 ",
		"IRP_MJ_FILE_SYSTEM_CONTROL               ",
		"IRP_MJ_DEVICE_CONTROL                           ",
		"IRP_MJ_INTERNAL_DEVICE_CONTROL           ",
		"IRP_MJ_SHUTDOWN                                 ",
		"IRP_MJ_LOCK_CONTROL                      ",
		"IRP_MJ_CLEANUP                                         ",
		"IRP_MJ_CREATE_MAILSLOT                          ",
		"IRP_MJ_QUERY_SECURITY                           ",
		"IRP_MJ_SET_SECURITY                      ",
		"IRP_MJ_POWER                                    ",
		"IRP_MJ_SYSTEM_CONTROL                           ",
		"IRP_MJ_DEVICE_CHANGE                            ",
		"IRP_MJ_QUERY_QUOTA                              ",
		"IRP_MJ_SET_QUOTA                                ",
		"IRP_MJ_PNP                                             ",
		};
		// 得到当前IRP的 栈结构
		PIO_STACK_LOCATION sTack = IoGetCurrentIrpStackLocation(Irp);
		// 根据索引打印对应的数组字符
		DbgPrint("%s\n", iRpName[sTack->MajorFunction]);
		// 设置IRP信息, 一定要处理
		// 返回给3环多少数据,没有填0
		Irp->IoStatus.Information = 0;
		// 设置IRP返回状态, 就是Getlasterror()函数获取的值
		Irp->IoStatus.Status = STATUS_SUCCESS;
		// 设置优先级，将IRP继续传递
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}
	
}





