#pragma once
#ifndef _IOSTRUCT_
#define _IOSTRUCT_

#include <ntifs.h>

#pragma pack(push, 0x1)

#define IoCommRead						0	// 读
#define IoCommWrite						1	// 写
#define IoCommEnumModuleInformation		2	// 获取指定模块信息
#define IoCommAllocatePool				3	// 指定进程申请内存
#define IoCommKernelCallbackTableInject 4	// 无痕注入

struct moudle_info
{
	uintptr_t bsae;
	uintptr_t size;
};

// 定义IO通信结构体
typedef struct _IO_COMM_CODE
{
	ULONG	ioCode;		// 通信码
	ULONG	Pid;		// 目标PID
	ULONG64	Address;	// 目标地址
	UCHAR*	DataBuffer;	// 储存读取数据的BUFFER
	ULONG	Size;		// 目标数据的大小
	ULONG	NtStatus;	// 返回状态
}IO_COMM_CODE, *PIO_COMM_CODE;

#pragma pack(pop)

#endif