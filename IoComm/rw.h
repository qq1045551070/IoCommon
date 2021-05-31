#pragma once
#ifndef _RW_
#define _RW_

#include <ntifs.h>

extern "C"
{
	namespace Rw
	{
		/// ������ȡ
		// @param HANDLE pid:			Ŀ�����PID
		// @param ULONG64 address:		Ŀ���ַ
		// @param void * read_buffer:	�洢��ȡ���ݵĻ�����
		// @param ULONG read_size:		��ȡ��С
		// @return NTSTATUS:			NTSTATUS
		NTSTATUS NormalRead(HANDLE pid, ULONG64 address, void* read_buffer, ULONG read_size);
		// ����д��
		NTSTATUS NormalWrite(HANDLE pid, ULONG64 address, void* write_buffer, ULONG write_size);

		// ���� MDL ӳ��
		PVOID MdlMapAddress(PMDL* pMdl, PVOID baseAddress, ULONG size, KPROCESSOR_MODE mode);
		// ж�� MDL ӳ��
		VOID MdlUnMapAddress(PMDL pMdl, PVOID mapAddress);

		/// Ŀ������д����ɶ���д��ִ���ڴ�
		// @param HANDLE pid:				Ŀ�����PID
		// @param ULONG size:				��Ҫ���ڴ��С
		// @param PVOID * ret_mem_address:	����Ŀ������ڴ��ַ
		// @return NTSTATUS:				NTSTATUS
		NTSTATUS NorAllocateMem(HANDLE pid, ULONG size, PVOID* ret_mem_address);
	}
}

#endif

