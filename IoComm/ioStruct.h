#pragma once
#ifndef _IOSTRUCT_
#define _IOSTRUCT_

#include <ntifs.h>

#pragma pack(push, 0x1)

#define IoCommRead						0	// ��
#define IoCommWrite						1	// д
#define IoCommEnumModuleInformation		2	// ��ȡָ��ģ����Ϣ
#define IoCommAllocatePool				3	// ָ�����������ڴ�
#define IoCommKernelCallbackTableInject 4	// �޺�ע��

struct moudle_info
{
	uintptr_t bsae;
	uintptr_t size;
};

// ����IOͨ�Žṹ��
typedef struct _IO_COMM_CODE
{
	ULONG	ioCode;		// ͨ����
	ULONG	Pid;		// Ŀ��PID
	ULONG64	Address;	// Ŀ���ַ
	UCHAR*	DataBuffer;	// �����ȡ���ݵ�BUFFER
	ULONG	Size;		// Ŀ�����ݵĴ�С
	ULONG	NtStatus;	// ����״̬
}IO_COMM_CODE, *PIO_COMM_CODE;

#pragma pack(pop)

#endif