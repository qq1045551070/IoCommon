#pragma once
#ifndef _INJECT_
#define _INJECT_

#include <ntifs.h>

extern "C"
{
	namespace Inject
	{
		// ��ʼ��
		void InitInject();

		/// KernelCallbackTableԶ��ת(R3:֧��, R0:��֧��, �˷�ʽΪ��������) 
		// @param HANDLE pid:			Ŀ�����ID
		// @param ULONG64 call_address:	Ҫ���õ�CALL��ַ(ע��Ҫ��Ŀ���ڴ���)
		// @return NTSTATUS:			NTSTATUS
		NTSTATUS KernelCallbackTableInjectRegistry(HANDLE pid, ULONG64 call_address);

		// APCԶ��ת
		// InstrumentationCallbackԶ��ת
	}
}

#endif

