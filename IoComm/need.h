#pragma once
#include <ntifs.h>

// я╟ур PreviousMode
static ULONG g_ThreadPreviousMode_offset = 0;
void __forceinline SetThreadPreviousMode(void* kthread, unsigned char mode, unsigned char* p_ori_mode)
{
	if (!g_ThreadPreviousMode_offset)
	{
		for (UCHAR* i = (UCHAR*)ExGetPreviousMode; *i != 0xcc; i++) {
			if (*i == 0xc3) {
				g_ThreadPreviousMode_offset = *(ULONG32*)(i - 0x4);
				break;
			}
		}
		if (!g_ThreadPreviousMode_offset)KdBreakPoint();
	}

	if (p_ori_mode)
		*(UCHAR*)p_ori_mode = *(UCHAR*)((ULONG64)kthread + g_ThreadPreviousMode_offset);
	*(UCHAR*)((ULONG64)kthread + g_ThreadPreviousMode_offset) = mode;
}