#ifndef _SecondHook_
#define _SecondHook_

#include <Windows.h>

//After checking, delete it;
BOOL WINAPI Check2ndHook();
BOOL WINAPI Write2ndHook(HANDLE hProcess, DWORD wdPid);

#endif
