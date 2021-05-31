#pragma once
#ifndef _FILE_
#define _FILE_

#include <ntifs.h>
#include "ioStruct.h"

extern "C"
{
	namespace File
	{
		// ��ס�ļ�����ֹ�ļ�У��
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool LockFile(IN wchar_t* FilePath);

		// ��ȡָ��ģ��ĺ���
		_IRQL_requires_max_(PASSIVE_LEVEL)
		ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module);

		// ��ȡָ��ģ����Ϣ
		NTSTATUS GetMoudleInformation(HANDLE pid, char* module_name, moudle_info* moduleinfo);
	}
}

#endif // !_FILE_

