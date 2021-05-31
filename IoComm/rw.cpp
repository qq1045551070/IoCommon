#include "rw.h"
#include "need.h"

extern "C"
{
	_Use_decl_annotations_
		NTSTATUS Rw::NormalRead(HANDLE pid, ULONG64 address, void* read_buffer, ULONG read_size)
	{
		if (!address || !MmIsAddressValid(read_buffer) || !read_size)
		{
			// ��������
			return STATUS_INVALID_PARAMETER;
		}

		if (address >= MmUserProbeAddress && (address + read_size) >= MmUserProbeAddress)
		{
			// ������ں˵�ֱַ�Ӷ�ȡ����
			if (!MmIsAddressValid((void*)address) || !MmIsAddressValid((void*)(address + read_size - 1)))
				return STATUS_ACCESS_VIOLATION;
			__try
			{
				memcpy(read_buffer, (void*)address, read_size);
				return STATUS_SUCCESS;
			}
			__except (1)
			{ return STATUS_ACCESS_VIOLATION; }
		}
		else if (address < MmUserProbeAddress && (address + read_size) >= MmUserProbeAddress)
		{
			// ��������
			return STATUS_INVALID_PARAMETER;
		}

		// ���������ʾΪ3����ַ��ȡ
		PEPROCESS eprocess;
		NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &eprocess);
		if (NtStatus != STATUS_SUCCESS)
			return NtStatus;

		void* temp_buffer = ExAllocatePool(NonPagedPool, read_size);
		RtlZeroBytes(temp_buffer, read_size);

		KAPC_STATE ApcState;
		KeStackAttachProcess(eprocess, &ApcState);

		if (!MmIsAddressValid((void*)address) || !MmIsAddressValid((void*)(address + read_size - 1)))
		{
			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(eprocess);
			ExFreePool(temp_buffer);
			return STATUS_ACCESS_VIOLATION;
		}

		__try
		{
			memcpy(temp_buffer, (void*)address, read_size);
		}
		__except (1)
		{
			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(eprocess); 
			ExFreePool(temp_buffer);
			return STATUS_ACCESS_VIOLATION;
		}
		
		KeUnstackDetachProcess(&ApcState);
		RtlCopyMemory(read_buffer, temp_buffer, read_size);

		ObDereferenceObject(eprocess);
		ExFreePool(temp_buffer);
		return STATUS_SUCCESS;
	}

	_Use_decl_annotations_
		NTSTATUS Rw::NormalWrite(HANDLE pid, ULONG64 address, void* write_buffer, ULONG write_size)
	{
		if (!address || !MmIsAddressValid(write_buffer) || !write_size)
		{
			// ��������
			return STATUS_INVALID_PARAMETER;
		}

		if (address >= MmUserProbeAddress && (address + write_size) >= MmUserProbeAddress)
		{
			// ������ں˵�ֱַ��д�뼴��
			if (!MmIsAddressValid((void*)address) || !MmIsAddressValid((void*)(address + write_size - 1)))
				return STATUS_ACCESS_VIOLATION;
			__try
			{
				memcpy((void*)address, write_buffer, write_size);
				return STATUS_SUCCESS;
			}
			__except (1)
			{ return STATUS_ACCESS_VIOLATION; }
		}
		else if (address < MmUserProbeAddress && (address + write_size) >= MmUserProbeAddress)
		{
			// ��������
			return STATUS_INVALID_PARAMETER;
		}

		// ���������ʾΪ3����ַд��
		PEPROCESS eprocess;
		NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &eprocess);
		if (NtStatus != STATUS_SUCCESS)
			return NtStatus;

		void* temp_buffer = ExAllocatePool(NonPagedPool, write_size);
		RtlZeroBytes(temp_buffer, write_size);
		RtlCopyMemory(temp_buffer, write_buffer, write_size);

		KAPC_STATE ApcState;
		KeStackAttachProcess(eprocess, &ApcState);

		if (!MmIsAddressValid((void*)address) || !MmIsAddressValid((void*)(address + write_size - 1)))
		{
			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(eprocess);
			ExFreePool(temp_buffer);
			return STATUS_ACCESS_VIOLATION;
		}

		__try
		{
			PMDL mdl = NULL;
			void* userMem = MdlMapAddress(&mdl, (void*)address, write_size, UserMode);
			if (userMem)
			{
				memcpy(userMem, temp_buffer, write_size);
				MdlUnMapAddress(mdl, (void*)address);
			}
		}
		__except (1)
		{
			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(eprocess); 
			ExFreePool(temp_buffer);
			return STATUS_ACCESS_VIOLATION;
		}

		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(eprocess);
		ExFreePool(temp_buffer);
		return STATUS_SUCCESS;
	}

	_Use_decl_annotations_
		PVOID Rw::MdlMapAddress(PMDL* pMdl, PVOID baseAddress, ULONG size, KPROCESSOR_MODE mode)
	{
		// build mdl struct
		PMDL mdl = IoAllocateMdl(baseAddress, size, FALSE, FALSE, NULL);
		BOOLEAN isLock = FALSE;
		PVOID mem = NULL;

		__try
		{
			// Ԥ��ȡ
			MmProbeAndLockPages(mdl, mode, IoReadAccess);
			isLock = TRUE;
			// mdl ӳ��
			mem = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		}
		__except (1)
		{
			if (isLock)
			{
				MmUnlockPages(mdl);
			}
			IoFreeMdl(mdl);
			*pMdl = NULL;
			return NULL;
		}

		if (mem)
		{
			*pMdl = mdl;
		}
		return mem;
	}
	
	_Use_decl_annotations_
		VOID Rw::MdlUnMapAddress(PMDL pMdl, PVOID mapAddress)
	{
		bool isUnLock = false;

		__try
		{
			MmUnmapLockedPages(mapAddress, pMdl);
			MmUnlockPages(pMdl);
			isUnLock = TRUE;	
			IoFreeMdl(pMdl);
			return;
		}
		__except (1)
		{
		}
		
		__try
		{
			if (isUnLock)
			{
				MmUnlockPages(pMdl);
			}
		}
		__except (1)
		{	
		}
		IoFreeMdl(pMdl);
	}
	
	_Use_decl_annotations_
		NTSTATUS Rw::NorAllocateMem(HANDLE pid, ULONG size, PVOID* ret_mem_address)
	{
		if (!size) return STATUS_INVALID_PARAMETER;

		// ��ȡR3�����ں˽ṹ��
		PEPROCESS eprocess;
		NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &eprocess);
		if (NtStatus != STATUS_SUCCESS)
			return NtStatus;

		// �ҿ�
		KAPC_STATE ApcState;
		KeStackAttachProcess(eprocess, &ApcState);

		do
		{
			UCHAR ori_mode;
			SetThreadPreviousMode(PsGetCurrentThread(), KernelMode, &ori_mode);
			PVOID exe_Mem = NULL;
			SIZE_T needSize = (SIZE_T)size;
			NtStatus = NtAllocateVirtualMemory(NtCurrentProcess(), &exe_Mem, 0, &needSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(NtStatus))
				break;
			RtlZeroMemory(exe_Mem, size);
			SetThreadPreviousMode(PsGetCurrentThread(), ori_mode, NULL);

			*ret_mem_address = exe_Mem;

		} while (false);

		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(eprocess);
		return NtStatus;
	}
}



