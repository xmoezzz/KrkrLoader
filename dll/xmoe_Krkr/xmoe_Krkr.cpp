/****************************************************************************
Copyright (c) 2014-2015 X'moe
xmoe.project@gmail.com
****************************************************************************/

#include "stdafx.h"
#include "xmoe_Krkr.h"
#include "Locale.h"
#include <wchar.h>
#include "SecondHook.h"
#include "Config.h"
#include "WinFile.h"
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Version.lib")

//Win8 and above
BOOL GetVersionVaild()
{
	OSVERSIONINFOEX osver;
	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((LPOSVERSIONINFO)&osver))
	{
		return (osver.dwMajorVersion >= 6) && (osver.dwMinorVersion > 1);
	}
	return FALSE;
}

PVOID pOldLoadLibaryA = NULL;
typedef HMODULE (WINAPI *PLoadLibaryA)(LPCSTR lpFileName);
HMODULE WINAPI MyLoadLibaryA(LPCSTR lpFileName)
{
	return ((PLoadLibaryA)pOldLoadLibaryA)(lpFileName);
}


PVOID pGetProcAddress = NULL;
typedef FARPROC(WINAPI *PGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	if (!strcmp(lpProcName, "GetSystemWow64DirectoryA"))
	{
		return NULL;
	}
	return ((PGetProcAddress)pGetProcAddress)(hModule, lpProcName);
}

BOOL WINAPI FindCodeSlow(const CHAR* start, ULONG size, const CHAR* Pattern, ULONG PatternLen)
{
	ULONG Strlen = PatternLen;
	ULONG iPos = 0;
	ULONG zPos = 0;
	BOOL Found = FALSE;
	while (iPos < size)
	{
		if (zPos == Strlen - 1)
		{
			Found = TRUE;
			break;
		}
		if (start[iPos] == Pattern[zPos])
		{
			iPos++;
			zPos++;
		}
		else
		{
			iPos++;
			zPos = 0;
		}
	}
	if (Found)
	{
		return TRUE;
	}
	return FALSE;
}



BOOL WINAPI IsKrkr2Module()
{
	static WCHAR Pattern[] = L"TVP(KIRIKIRI) 2 core / Scripting Platform for Win32";
	WCHAR FileName[MAX_PATH * 2] = { 0 };
	GetModuleFileNameExW(GetCurrentProcess(), NULL, FileName, MAX_PATH * 2);

	BOOL Result = FALSE;
	WinFile File;

	if (File.Open(FileName, WinFile::FileRead) == S_OK)
	{
		DWORD RawFileSize = File.GetSize32();
		PBYTE RawBuffer = nullptr;
		RawBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, RawFileSize);
		if (RawBuffer)
		{
			File.Read(RawBuffer, RawFileSize);
			if (FindCodeSlow((const char*)RawBuffer, RawFileSize, (char*)Pattern, lstrlenW(Pattern) * 2))
			{
				Result = TRUE;
			}
			HeapFree(GetProcessHeap(), 0, RawBuffer);
		}
		File.Release();
	}

	return Result;
}


HRESULT WINAPI InitHook()
{
	bool bCheckProcess;
	bool bTryHack;
	bool bRunLE;
	wstring Path;

	bool ret = ReadLogFile(Path, bCheckProcess, bTryHack, bRunLE);

	//Removed some code related to shell-hacking due to some reason.
	//In this way, code always won't work at all.
	if (ret && bCheckProcess)
	{
		if (IsKrkr2Module())
		{
			Init2ndHook();
		}
	}
	if (ret && bRunLE)
	{
		RunInlineLocale();
	}
	if (!GetVersionVaild())
	{
		return S_FALSE;
	}
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	pOldLoadLibaryA = DetourFindFunction("Kernel32.dll", "LoadLibaryA");
	DetourAttach(&pOldLoadLibaryA, MyLoadLibaryA);
	DetourTransactionCommit();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	pGetProcAddress = DetourFindFunction("Kernel32.dll", "GetProcAddress");
	DetourAttach(&pGetProcAddress, MyGetProcAddress);
	DetourTransactionCommit();

	return S_OK;
}



HRESULT WINAPI UnInitHook()
{
	return S_OK;
}
