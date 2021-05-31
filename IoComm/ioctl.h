#pragma once
#ifndef _IOCTL_
#define _IOCTL_

#include <ntifs.h>
#include "ioStruct.h"

// IO通信码
#define CTL_IO_COMM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED,  FILE_ANY_ACCESS)

extern "C"
{
	// 定义IoCallBack原型
	typedef NTSTATUS(*PIOCTLCALLBACK)(IN PIO_COMM_CODE);

	namespace Ioctl
	{
		// Ioctl初始化需要的符号
		_IRQL_requires_max_(PASSIVE_LEVEL)
		void IoctlInit();

		// 注册IO通信回调函数
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool RegistryIoctlCallBack(IN PIOCTLCALLBACK IoCallBack);

		// 卸载IO通信回调函数
		_IRQL_requires_max_(PASSIVE_LEVEL)
		void UnRegistryIoctlCallBack();

		// 驱动拦截通信
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool DriverInterceptIoComm(IN wchar_t* DriverSymbolicLink = L"\\Driver\\Null");

		// 随机获取符号名称
		_IRQL_requires_max_(PASSIVE_LEVEL)
		PUNICODE_STRING GetSymRandName();

		// 将随机链接符号写入NTDLL
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool SymLinkNameWriteNtdll(PUNICODE_STRING SysmbolicLinkName);

		// 根据名称获取进程结构体
		_IRQL_requires_max_(PASSIVE_LEVEL)
		PEPROCESS GetProcessObjectByName(wchar_t* wProcessName);

		/* IRP_MJ_DEVICE_CONTROL 处理函数 */
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS DrvIoControlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

		/* 默认IRP处理函数【什么也不做】 */
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS DrvDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
	}
}

#endif
