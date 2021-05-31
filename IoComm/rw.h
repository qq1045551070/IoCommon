#pragma once
#ifndef _RW_
#define _RW_

#include <ntifs.h>

extern "C"
{
	namespace Rw
	{
		/// 正常读取
		// @param HANDLE pid:			目标进程PID
		// @param ULONG64 address:		目标地址
		// @param void * read_buffer:	存储读取数据的缓冲区
		// @param ULONG read_size:		读取大小
		// @return NTSTATUS:			NTSTATUS
		NTSTATUS NormalRead(HANDLE pid, ULONG64 address, void* read_buffer, ULONG read_size);
		// 正常写入
		NTSTATUS NormalWrite(HANDLE pid, ULONG64 address, void* write_buffer, ULONG write_size);

		// 构建 MDL 映射
		PVOID MdlMapAddress(PMDL* pMdl, PVOID baseAddress, ULONG size, KPROCESSOR_MODE mode);
		// 卸载 MDL 映射
		VOID MdlUnMapAddress(PMDL pMdl, PVOID mapAddress);

		/// 目标进程中创建可读可写可执行内存
		// @param HANDLE pid:				目标进程PID
		// @param ULONG size:				需要的内存大小
		// @param PVOID * ret_mem_address:	返回目标进程内存地址
		// @return NTSTATUS:				NTSTATUS
		NTSTATUS NorAllocateMem(HANDLE pid, ULONG size, PVOID* ret_mem_address);
	}
}

#endif

