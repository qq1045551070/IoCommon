#pragma once
#ifndef _FILE_
#define _FILE_

#include <ntifs.h>
#include "ioStruct.h"

extern "C"
{
	namespace File
	{
		// 锁住文件，防止文件校验
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool LockFile(IN wchar_t* FilePath);

		// 获取指定模块的函数
		_IRQL_requires_max_(PASSIVE_LEVEL)
		ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module);

		// 获取指定模块信息
		NTSTATUS GetMoudleInformation(HANDLE pid, char* module_name, moudle_info* moduleinfo);
	}
}

#endif // !_FILE_


