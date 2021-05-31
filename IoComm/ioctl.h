#pragma once
#ifndef _IOCTL_
#define _IOCTL_

#include <ntifs.h>
#include "ioStruct.h"

// IOͨ����
#define CTL_IO_COMM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED,  FILE_ANY_ACCESS)

extern "C"
{
	// ����IoCallBackԭ��
	typedef NTSTATUS(*PIOCTLCALLBACK)(IN PIO_COMM_CODE);

	namespace Ioctl
	{
		// Ioctl��ʼ����Ҫ�ķ���
		_IRQL_requires_max_(PASSIVE_LEVEL)
		void IoctlInit();

		// ע��IOͨ�Żص�����
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool RegistryIoctlCallBack(IN PIOCTLCALLBACK IoCallBack);

		// ж��IOͨ�Żص�����
		_IRQL_requires_max_(PASSIVE_LEVEL)
		void UnRegistryIoctlCallBack();

		// ��������ͨ��
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool DriverInterceptIoComm(IN wchar_t* DriverSymbolicLink = L"\\Driver\\Null");

		// �����ȡ��������
		_IRQL_requires_max_(PASSIVE_LEVEL)
		PUNICODE_STRING GetSymRandName();

		// ��������ӷ���д��NTDLL
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool SymLinkNameWriteNtdll(PUNICODE_STRING SysmbolicLinkName);

		// �������ƻ�ȡ���̽ṹ��
		_IRQL_requires_max_(PASSIVE_LEVEL)
		PEPROCESS GetProcessObjectByName(wchar_t* wProcessName);

		/* IRP_MJ_DEVICE_CONTROL ������ */
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS DrvIoControlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

		/* Ĭ��IRP��������ʲôҲ������ */
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS DrvDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
	}
}

#endif
