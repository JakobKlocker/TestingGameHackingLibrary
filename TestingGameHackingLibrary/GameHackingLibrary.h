#pragma once
#include <Windows.h>


struct g_infos {
	HANDLE	procHandel;
	DWORD	procId;
	HMODULE ntdllHandel;
	HMODULE ntdllHandelCopy;
};