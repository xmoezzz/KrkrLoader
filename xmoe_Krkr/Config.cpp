#include "Config.h"

bool ReadLogFile(wstring& Path, bool& CheckProcess, bool& TryHack, bool& runLE)
{
	HANDLE fileHandle = CreateFileW(L"KrkrLaunch.ini", GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		Path = L"";
		return false;
	}
	else
	{
		SetFilePointer(fileHandle, 0, NULL, FILE_BEGIN);

		char Signature[16] = { 0 };
		DWORD Readed = 0;
		ReadFile(fileHandle, Signature, 16, &Readed, NULL);
		SetFilePointer(fileHandle, 16, NULL, FILE_BEGIN);
		if (memcmp(Signature, "STmoeSTmoechu>_<", 16))
		{
			CloseHandle(fileHandle);
			Path = L"";
			return false;
		}
		DWORD Length = 0;
		ReadFile(fileHandle, &Length, 4, &Readed, NULL);
		if (Length > MAX_PATH)
		{
			CloseHandle(fileHandle);
			Path = L"";
			return false;
		}
		SetFilePointer(fileHandle, 20, NULL, FILE_BEGIN);
		wchar_t FilePath[MAX_PATH] = { 0 };
		try
		{
			ReadFile(fileHandle, FilePath, Length * 2, &Readed, NULL);
		}
		catch (...)
		{
			CloseHandle(fileHandle);
			Path = L"";
			return false;
		}
		SetFilePointer(fileHandle, 20 + Length * 2, NULL, FILE_BEGIN);
		BYTE bCheckProcess = 0;
		BYTE bTryHack = 0;
		BYTE bRunLe = 0;

		ReadFile(fileHandle, &bCheckProcess, 1, &Readed, NULL);
		//SetFilePointer(fileHandle, 20 + Length * 2 + 1, NULL, FILE_BEGIN);
		ReadFile(fileHandle, &bTryHack, 1, &Readed, NULL);
		//SetFilePointer(fileHandle, 20 + Length * 2 + 2, NULL, FILE_BEGIN);
		ReadFile(fileHandle, &bRunLe, 1, &Readed, NULL);
		Path = FilePath;

		CheckProcess = bCheckProcess;
		TryHack = bTryHack;
		runLE = bRunLe;
		return true;
	}
}
