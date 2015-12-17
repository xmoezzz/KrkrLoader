
// KrkrLoader.cpp : 定义应用程序的类行为。
//

#include "stdafx.h"
#include "KrkrLoader.h"
#include "KrkrLoaderDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CKrkrLoaderApp

BEGIN_MESSAGE_MAP(CKrkrLoaderApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CKrkrLoaderApp 构造

CKrkrLoaderApp::CKrkrLoaderApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的一个 CKrkrLoaderApp 对象

CKrkrLoaderApp theApp;


// CKrkrLoaderApp 初始化

BOOL CKrkrLoaderApp::InitInstance()
{
	CWinApp::InitInstance();


	// 创建 shell 管理器，以防对话框包含
	// 任何 shell 树视图控件或 shell 列表视图控件。
	CShellManager *pShellManager = new CShellManager;

	// 激活“Windows Native”视觉管理器，以便在 MFC 控件中启用主题
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	SetRegistryKey(_T("KrkrLoader"));

	CString Path;
	BOOL bCheckProcess = FALSE;
	BOOL bTryHack = FALSE;
	BOOL bRunLE = FALSE;
	if (OnInit::ReadLog(Path, bCheckProcess, bTryHack, bRunLE))
	{
		if (OnInit::CheckFile(Path))
		{
			BOOL s = FALSE;
			BOOL ret = OnInit::IsExeFile(Path, s);
			if (ret && s)
			{
				if (OnInit::Inject(Path))
				{
					// 删除上面创建的 shell 管理器。
					if (pShellManager != NULL)
					{
						delete pShellManager;
					}

					return FALSE;
				}
			}
		}
	}
	/************************/

	CKrkrLoaderDlg dlg;
	m_pMainWnd = &dlg;
	dlg.ShowWindow(SW_SHOW);
	INT_PTR nResponse = dlg.DoModal();

	// 删除上面创建的 shell 管理器。
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	return FALSE;
}




bool FileIsExist(const wchar_t* FileName)
{
	HANDLE fileHandle = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	bool ret = true;
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		ret = false;
	}
	CloseHandle(fileHandle);
	return ret;
}


//获得DOS头
LPVOID GetDosHeader(LPVOID lpFile)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)lpFile;

	return (LPVOID)pDosHeader;
}

//获得NT头
LPVOID GetNtHeader(LPVOID lpFile, BOOL& bX64)
{
	bX64 = FALSE;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	PIMAGE_NT_HEADERS64 pHeaders64 = NULL;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)GetDosHeader(lpFile);
	//判断是否合法
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//判断是不是正常的PE文件
	if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pNtHeader32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) //64bit
	{
		bX64 = TRUE;
		pHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD)pDosHeader + pDosHeader->e_lfanew);
		return pHeaders64;
	}

	return pNtHeader32;
}

//获得可选头
LPVOID GetOptionHeader(LPVOID lpFile, BOOL& bX64)
{
	bX64 = FALSE;
	LPVOID pOptionHeader = NULL;
	BOOL bX64Nt = FALSE;

	LPVOID pNtHeader = (LPVOID)GetNtHeader(lpFile, bX64Nt);
	if (pNtHeader == NULL)
		return NULL;

	if (bX64Nt) //64bit
	{
		bX64 = TRUE;
		pOptionHeader = (LPVOID)PIMAGE_OPTIONAL_HEADER64((DWORD)pNtHeader + sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD));
	}
	else
	{
		pOptionHeader = (LPVOID)PIMAGE_OPTIONAL_HEADER32((DWORD)pNtHeader + sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD));
	}
	return pOptionHeader;
}

/*
*  获取字段
*/
BOOL IsDigiSigEX(HANDLE hFile)
{
	if (hFile == INVALID_HANDLE_VALUE)  //文件对象
		return FALSE;
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpFile = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFile == NULL)  //文件视图对象
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return FALSE;
	}

	IMAGE_DATA_DIRECTORY secData = { 0 };
	LPVOID pOptionHeader = NULL;
	BOOL bX64Opheader = FALSE;

	pOptionHeader = (LPVOID)GetOptionHeader(lpFile, bX64Opheader);
	if (pOptionHeader != NULL && bX64Opheader)
	{
		secData = ((PIMAGE_OPTIONAL_HEADER64)pOptionHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}
	else if (pOptionHeader != NULL)
	{
		secData = ((PIMAGE_OPTIONAL_HEADER32)pOptionHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}

	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	if ((secData.VirtualAddress != 0) && (secData.Size != 0))
		return TRUE;
	return FALSE;
}
//A版函数
BOOL IsDigiSigA(LPCSTR pPath)
{
	HANDLE hFile = CreateFileA(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	return IsDigiSigEX(hFile);
}
//W版函数
BOOL IsDigiSigW(LPCWSTR pPath)
{
	HANDLE hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	return IsDigiSigEX(hFile);
}

//实际判断PE文件操作
BOOL IsPEFileEX(HANDLE hFile, BOOL &bIsSucceed)
{
	if (hFile == INVALID_HANDLE_VALUE)  //文件对象
		return FALSE;
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpFile = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFile == NULL)  //文件视图对象
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	//取得Dos头部
	pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(lpFile);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return TRUE;
	}

	//获取NT头
	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//判断是不是PE文件
	if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
	{
		UnmapViewOfFile(lpFile);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return TRUE;
	}

	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	bIsSucceed = TRUE;
	return TRUE;
}

BOOL IsPEFileA(LPCSTR pPath, BOOL &bIsSucceed)
{
	bIsSucceed = FALSE;
	HANDLE hFile = CreateFileA(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	return IsPEFileEX(hFile, bIsSucceed);
}
//W版
BOOL IsPEFileW(LPCWSTR pPath, BOOL &bIsSucceed)
{
	bIsSucceed = FALSE;
	HANDLE hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	return IsPEFileEX(hFile, bIsSucceed);
}


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
		SetFilePointer(fileHandle, 20 + Length * 2 + 1, NULL, FILE_BEGIN);
		ReadFile(fileHandle, &bTryHack, 1, &Readed, NULL);
		SetFilePointer(fileHandle, 20 + Length * 2 + 2, NULL, FILE_BEGIN);
		ReadFile(fileHandle, &bRunLe, 1, &Readed, NULL);
		Path = FilePath;

		CheckProcess = bCheckProcess;
		TryHack = bTryHack;
		runLE = bRunLe;
		return true;
	}
}

void WriteLogFile(const wchar_t* Path, bool CheckProcess, bool TryHack, bool runLE)
{
	HANDLE hFile = CreateFile(_TEXT("KrkrLaunch.ini"), GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return;
	}
	else
	{
		BYTE xOK = 1;
		BYTE xNo = 0;
		DWORD nRet = 0;
		WriteFile(hFile, "STmoeSTmoechu>_<", 16, &nRet, NULL);
		DWORD Length = wcslen(Path);
		WriteFile(hFile, &Length, 4, &nRet, NULL);
		WriteFile(hFile, (const char*)Path, Length * 2, &nRet, NULL);
		if (CheckProcess)
		{
			WriteFile(hFile, &xOK, 1, &nRet, NULL);
		}
		else
		{
			WriteFile(hFile, &xNo, 1, &nRet, NULL);
		}
		if (TryHack)
		{
			WriteFile(hFile, &xOK, 1, &nRet, NULL);
		}
		else
		{
			WriteFile(hFile, &xNo, 1, &nRet, NULL);
		}
		if (runLE)
		{
			WriteFile(hFile, &xOK, 1, &nRet, NULL);
		}
		else
		{
			WriteFile(hFile, &xNo, 1, &nRet, NULL);
		}
		CloseHandle(hFile);
	}
}


typedef BOOL(WINAPI* Proc_CreateProcessW)(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

typedef HMODULE(WINAPI* Func_LoadLibraryW)(LPCWSTR lpLibFileName);


BYTE* mov_eax_xx(BYTE* lpCurAddres, DWORD eax)
{
	*lpCurAddres = 0xB8;
	*(DWORD*)(lpCurAddres + 1) = eax;
	return lpCurAddres + 5;
}

BYTE* mov_ebx_xx(BYTE* lpCurAddres, DWORD ebx)
{
	*lpCurAddres = 0xBB;
	*(DWORD*)(lpCurAddres + 1) = ebx;
	return lpCurAddres + 5;
}

BYTE* mov_ecx_xx(BYTE* lpCurAddres, DWORD ecx)
{
	*lpCurAddres = 0xB9;
	*(DWORD*)(lpCurAddres + 1) = ecx;
	return lpCurAddres + 5;
}

BYTE* mov_edx_xx(BYTE* lpCurAddres, DWORD edx)
{
	*lpCurAddres = 0xBA;
	*(DWORD*)(lpCurAddres + 1) = edx;
	return lpCurAddres + 5;
}

BYTE* mov_esi_xx(BYTE* lpCurAddres, DWORD esi)
{
	*lpCurAddres = 0xBE;
	*(DWORD*)(lpCurAddres + 1) = esi;
	return lpCurAddres + 5;
}

BYTE* mov_edi_xx(BYTE* lpCurAddres, DWORD edi)
{
	*lpCurAddres = 0xBF;
	*(DWORD*)(lpCurAddres + 1) = edi;
	return lpCurAddres + 5;
}

BYTE* mov_ebp_xx(BYTE* lpCurAddres, DWORD ebp)
{
	*lpCurAddres = 0xBD;
	*(DWORD*)(lpCurAddres + 1) = ebp;
	return lpCurAddres + 5;
}

BYTE* mov_esp_xx(BYTE* lpCurAddres, DWORD esp)
{
	*lpCurAddres = 0xBC;
	*(DWORD*)(lpCurAddres + 1) = esp;
	return lpCurAddres + 5;
}

BYTE* mov_eip_xx(BYTE* lpCurAddres, DWORD eip, DWORD newEip)
{
	if (!newEip)
	{
		newEip = (DWORD)lpCurAddres;
	}

	*lpCurAddres = 0xE9;
	*(DWORD*)(lpCurAddres + 1) = eip - (newEip + 5);
	return lpCurAddres + 5;
}

BYTE* push_xx(BYTE* lpCurAddres, DWORD dwAdress)
{

	*lpCurAddres = 0x68;
	*(DWORD*)(lpCurAddres + 1) = dwAdress;

	return lpCurAddres + 5;
}

BYTE* Call_xx(BYTE* lpCurAddres, DWORD eip, DWORD newEip)
{
	if (!newEip)
	{
		newEip = (DWORD)lpCurAddres;
	}

	*lpCurAddres = 0xE8;
	*(DWORD*)(lpCurAddres + 1) = eip - (newEip + 5);
	return lpCurAddres + 5;
}

BOOL SuspendTidAndInjectCode(HANDLE hProcess, HANDLE hThread, DWORD dwFuncAdress, const BYTE * lpShellCode, size_t uCodeSize)
{
	SIZE_T NumberOfBytesWritten = 0;
	BYTE ShellCodeBuf[0x480];
	CONTEXT Context;
	DWORD flOldProtect = 0;
	LPBYTE lpCurESPAddress = NULL;
	LPBYTE lpCurBufAdress = NULL;
	BOOL bResult = FALSE;


	// 挂载起线程
	SuspendThread(hThread);

	memset(&Context, 0, sizeof(Context));
	Context.ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(hThread, &Context))
	{
		// 在对方线程中开辟一个 0x480 大小的局部空
		lpCurESPAddress = (LPBYTE)((Context.Esp - 0x480) & 0xFFFFFFE0);

		// 获取指针 用指针来操作
		lpCurBufAdress = &ShellCodeBuf[0];

		if (lpShellCode)
		{
			memcpy(ShellCodeBuf + 128, lpShellCode, uCodeSize);
			lpCurBufAdress = push_xx(lpCurBufAdress, (DWORD)lpCurESPAddress + 128); // push
			lpCurBufAdress = Call_xx(lpCurBufAdress, dwFuncAdress, (DWORD)lpCurESPAddress + (DWORD)lpCurBufAdress - (DWORD)&ShellCodeBuf); //Call
		}

		lpCurBufAdress = mov_eax_xx(lpCurBufAdress, Context.Eax);
		lpCurBufAdress = mov_ebx_xx(lpCurBufAdress, Context.Ebx);
		lpCurBufAdress = mov_ecx_xx(lpCurBufAdress, Context.Ecx);
		lpCurBufAdress = mov_edx_xx(lpCurBufAdress, Context.Edx);
		lpCurBufAdress = mov_esi_xx(lpCurBufAdress, Context.Esi);
		lpCurBufAdress = mov_edi_xx(lpCurBufAdress, Context.Edi);
		lpCurBufAdress = mov_ebp_xx(lpCurBufAdress, Context.Ebp);
		lpCurBufAdress = mov_esp_xx(lpCurBufAdress, Context.Esp);
		lpCurBufAdress = mov_eip_xx(lpCurBufAdress, Context.Eip, (DWORD)lpCurESPAddress + (DWORD)lpCurBufAdress - (DWORD)&ShellCodeBuf);
		Context.Esp = (DWORD)(lpCurESPAddress - 4);
		Context.Eip = (DWORD)lpCurESPAddress;

		if (VirtualProtectEx(hProcess, lpCurESPAddress, 0x480, PAGE_EXECUTE_READWRITE, &flOldProtect)
			&& WriteProcessMemory(hProcess, lpCurESPAddress, &ShellCodeBuf, 0x480, &NumberOfBytesWritten)
			&& FlushInstructionCache(hProcess, lpCurESPAddress, 0x480)
			&& SetThreadContext(hThread, &Context))
		{
			bResult = TRUE;
		}

	}

	// 回复线程
	ResumeThread(hThread);

	return TRUE;
}

DWORD GetFuncAdress()
{
	return (DWORD)GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryW");
}

BOOL WINAPI CreateProcessWithDllW(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	LPWSTR lpDllFullPath,
	Proc_CreateProcessW FuncAdress
	)
{
	BOOL bResult = FALSE;
	size_t uCodeSize = 0;
	DWORD dwCreaFlags;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	if (FuncAdress == NULL)
	{
		FuncAdress = CreateProcessW;
	}


	// 设置创建就挂起进程
	dwCreaFlags = dwCreationFlags | CREATE_SUSPENDED;
	if (CreateProcessW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreaFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		&pi
		))
	{
		if (lpDllFullPath)
			uCodeSize = 2 * wcslen(lpDllFullPath) + 2;
		else
			uCodeSize = 0;

		// 得到LoadLibraryW 的地址
		DWORD dwLoadDllProc = GetFuncAdress();

		// 挂起线程 写入Shellcode
		if (SuspendTidAndInjectCode(pi.hProcess, pi.hThread, dwLoadDllProc, (BYTE*)lpDllFullPath, uCodeSize))
		{
			if (lpProcessInformation)
				memcpy(lpProcessInformation, &pi, sizeof(PROCESS_INFORMATION));

			if (!(dwCreationFlags & CREATE_SUSPENDED))
				ResumeThread(pi.hThread);

			bResult = TRUE;
		}
	}

	return bResult;
}



BOOL Inject(wchar_t* ExePath)
{
	WCHAR *wszPath = ExePath;
	WCHAR wszDll[] = L"xmoe_Krkr.dll";

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	BOOL result = CreateProcessWithDllW(NULL, wszPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi, wszDll, NULL);
	if (!result)
	{
		DWORD Error = GetLastError();
		WCHAR Info[200] = { 0 };
		wsprintfW(Info, L"Failed to inject.\nReason : 0x%08x", Error);
		::MessageBoxW(NULL, Info, L"QAQ", MB_OK);
	}
	return result;
}

