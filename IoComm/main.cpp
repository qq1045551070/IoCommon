#include "main.h"
#include "ioctl.h"
#include "rw.h"
#include "file.h"
#include "inject.h"

extern "C"
{	
#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

	NTSTATUS MYPIOCTLCALLBACK(IN PIO_COMM_CODE IoCommCode)
	{
		ULONG	ioCode = IoCommCode->ioCode;
		
		ULONG	 Pid		= IoCommCode->Pid;
		ULONG64	 Address	= IoCommCode->Address;
		UCHAR*	 DataBuffer	= IoCommCode->DataBuffer;
		ULONG	 Size		= IoCommCode->Size;
		NTSTATUS NtStatus	= IoCommCode->NtStatus;
		
		KdPrintEx((77, 0, "%x, %x, %s, %x, %x\r\n", Pid, Address, DataBuffer, Size, NtStatus));
		
		switch (ioCode)
		{
		case IoCommRead:
		{
			// ��ȡĿ������
			IoCommCode->NtStatus = Rw::NormalRead((HANDLE)Pid, Address, DataBuffer, Size);
		}
			break;
		case IoCommWrite:
		{
			// д�����ݵ�Ŀ��
			IoCommCode->NtStatus = Rw::NormalWrite((HANDLE)Pid, Address, DataBuffer, Size);
		}
			break;
		case IoCommEnumModuleInformation:
		{
			// ��ȡָ��ģ����Ϣ
			IoCommCode->NtStatus = File::GetMoudleInformation((HANDLE)Pid, (char *)Address, (moudle_info*)DataBuffer);
		}
			break;
		case IoCommAllocatePool:
		{
			// ��ָ�������������ڴ�
			IoCommCode->NtStatus = Rw::NorAllocateMem((HANDLE)Pid, Size, (PVOID*)DataBuffer);
		}
			break;
		case IoCommKernelCallbackTableInject:
		{
			// �޺�ע��
			IoCommCode->NtStatus = Inject::KernelCallbackTableInjectRegistry(Pid, Address);
		}
			break;
		default:
			IoCommCode->NtStatus = STATUS_UNSUCCESSFUL;
			break;
		}

		return STATUS_SUCCESS;
	}

	_Use_decl_annotations_
		NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
	{
		UNREFERENCED_PARAMETER(DriverObject);
		UNREFERENCED_PARAMETER(RegPath);
		NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
		//DriverObject->DriverUnload = NULL;
		
		Ioctl::IoctlInit();
		if (Ioctl::RegistryIoctlCallBack(MYPIOCTLCALLBACK))			
		{
			NtStatus = STATUS_SUCCESS;
			KdPrintEx((77, 0, "ע��IO�ص��ɹ�! \n"));
		}
		
		KdPrintEx((77, 0, "�����������سɹ�! \r\n"));
		return NtStatus;
	}

	_Use_decl_annotations_
		VOID DriverUnload(PDRIVER_OBJECT DriverObject)
	{
		Ioctl::UnRegistryIoctlCallBack();
	}
}