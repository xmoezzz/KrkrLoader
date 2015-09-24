#include "SecondHook.h"


BOOL WINAPI Check2ndHook()
{
	HANDLE fileHandle = CreateFileW(L"Process.ini", GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
	{
		SetFilePointer(fileHandle, 0, NULL, FILE_BEGIN);

		char Signature[16] = { 0 };
		DWORD Readed = 0;
		ReadFile(fileHandle, Signature, 16, &Readed, NULL);
		SetFilePointer(fileHandle, 16, NULL, FILE_BEGIN);
		if (memcmp(Signature, "STmoeSTmoechu@_@", 16))
		{
			CloseHandle(fileHandle);
			DeleteFileW(L"Process.ini");
			return false;
		}
		DWORD ProcessHandle = -1;
		DWORD ProcessId = 0;
		ReadFile(fileHandle, &ProcessHandle, 4, &Readed, NULL);
		if (ProcessHandle != (DWORD)GetCurrentProcess())
		{
			CloseHandle(fileHandle);
			DeleteFileW(L"Process.ini");
			return FALSE;
		}
		ReadFile(fileHandle, &ProcessId, 4, &Readed, NULL);
		if (ProcessId != (DWORD)GetCurrentProcessId())
		{
			CloseHandle(fileHandle);
			DeleteFileW(L"Process.ini");
			return FALSE;
		}
		DeleteFileW(L"Process.ini");
		CloseHandle(fileHandle);
		return TRUE;
	}
}


BOOL WINAPI Write2ndHook(HANDLE hProcess, DWORD wdPid)
{
	HANDLE hFile = CreateFile(L"Process.ini", GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	DWORD nRet = 0;
	WriteFile(hFile, "STmoeSTmoechu@_@", 16, &nRet, NULL);

	WriteFile(hFile, &hProcess, 4, &nRet, NULL);
	WriteFile(hFile, &wdPid,    4, &nRet, NULL);
	CloseHandle(hFile);
	return TRUE;
}
