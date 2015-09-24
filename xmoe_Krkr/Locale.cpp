#include "Locale.h"
#include <Windows.h>
#include "detours.h"
#include "tp_stub.h"
#include "TextStream.h"


/**************************************/
//On Hooking CreateProcess


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


typedef BOOL(WINAPI* Proc_CreateProcessA)(LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
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

	SuspendThread(hThread);

	memset(&Context, 0, sizeof(Context));
	Context.ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(hThread, &Context))
	{
		lpCurESPAddress = (LPBYTE)((Context.Esp - 0x480) & 0xFFFFFFE0);

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

		DWORD dwLoadDllProc = GetFuncAdress();

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



BOOL WINAPI CreateProcessWithDllA(LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	LPWSTR lpDllFullPath,
	Proc_CreateProcessA FuncAdress
	)
{
	BOOL bResult = FALSE;
	size_t uCodeSize = 0;
	DWORD dwCreaFlags;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	if (FuncAdress == NULL)
	{
		FuncAdress = CreateProcessA;
	}

	dwCreaFlags = dwCreationFlags | CREATE_SUSPENDED;
	if (CreateProcessA(lpApplicationName,
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

		DWORD dwLoadDllProc = GetFuncAdress();

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


BOOL WINAPI HookCreateProcessA(LPCSTR  lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	WCHAR wszDll[] = L"xmoe_Krkr.dll";

	BOOL result = CreateProcessWithDllA(lpApplicationName, lpCommandLine,
		NULL, NULL, FALSE, 0, NULL, NULL, lpStartupInfo, lpProcessInformation, wszDll, NULL);
	
	if (result)
	{
		Write2ndHook(lpProcessInformation->hProcess, lpProcessInformation->dwProcessId);
	}
	return result;
}


BOOL WINAPI HookCreateProcessW(LPCWSTR  lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	WCHAR wszDll[] = L"xmoe_Krkr.dll";

	BOOL result = CreateProcessWithDllW(lpApplicationName, lpCommandLine,
		NULL, NULL, FALSE, 0, NULL, NULL, lpStartupInfo, lpProcessInformation, wszDll, NULL);

	if (result)
	{
		Write2ndHook(lpProcessInformation->hProcess, lpProcessInformation->dwProcessId);
	}
	return result;
}


//
VOID WINAPI Init2ndHook()
{
	FARPROC pfCreateProcessA = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CreateProcessA");
	FARPROC pfCreateProcessW = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CreateProcessW");

	IATPatch("Kernel32.dll", pfCreateProcessA, (PROC)HookCreateProcessA);
	IATPatch("Kernel32.dll", pfCreateProcessW, (PROC)HookCreateProcessW);
}


PVOID pfTVPCreateTextStreamForReadByEncoding = NULL;
typedef iTJSTextReadStream * (__stdcall * PfunTVPCreateTextStreamForReadByEncoding)(const ttstr &, const ttstr &, const ttstr &);

//Test Mode
//This Function wasn't registered in TJS VM.(Krkrz function
//So When we try to query this function, system will raise an exception to warn you.
//If this function were registered, things will be must easier. >_<
iTJSTextReadStream* WINAPI HookTVPCreateTextStreamForRead(const ttstr & name,
	const ttstr & modestr)
{
	return (PfunTVPCreateTextStreamForReadByEncoding(pfTVPCreateTextStreamForReadByEncoding))(name, modestr, TJS_W("Shift_JIS"));
}

//Hook class tTVPTextReadStream
//Using class tTVPTextReadStreamXmoe to instead of it.
//Note:
//Using InlineHook(or just change the IAT) to modity MultiByteToWideChar is unsafe,
//for Krkr2 using the this API to do many things(Not only codepage conversation).
//(But we can use this way in krkrz)
iTJSTextReadStream* WINAPI HookTVPCreateTextStreamForReadV2(const ttstr & name,
	const ttstr & modestr)
{
	//Class tTVPTextReadStreamXmoe inherits class iTJSTextReadStream.
	//Try to implement member functions in your own way(Compiler will overwrite the vtable).
	return new tTVPTextReadStreamXmoe(name, modestr, TJS_W("Shift_JIS"));
}

PVOID WINAPI GetFunctionProc()
{
	if (!pfTVPCreateTextStreamForReadByEncoding)
	{
		static char funcname[] = "iTJSTextReadStream * ::TVPCreateTextStreamForReadByEncoding(const ttstr &,const ttstr &,const ttstr &)";
		pfTVPCreateTextStreamForReadByEncoding = TVPGetImportFuncPtr(funcname);
		return pfTVPCreateTextStreamForReadByEncoding;
	}
}

typedef iTVPFunctionExporter*   (WINAPI *TVPGetFunctionExporterFunc)();
TVPGetFunctionExporterFunc pfTVPGetFunctionExporter = nullptr;

iTVPFunctionExporter* WINAPI HookTVPGetFunctionExporter()
{
	iTVPFunctionExporter* result = pfTVPGetFunctionExporter();
	TVPInitImportStub(result);

	static char funcname1[] = "iTJSTextReadStream * ::TVPCreateTextStreamForRead(const ttstr &,const ttstr &)";
	PVOID pfTVPCreateTextStreamForRead = TVPGetImportFuncPtr(funcname1);

	//GetFunctionProc()
	if (pfTVPCreateTextStreamForRead)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID*)&pfTVPCreateTextStreamForRead, HookTVPCreateTextStreamForReadV2);
		DetourTransactionCommit();
	}
	else
	{
		MessageBoxW(NULL, L"Failed to Query Function Ptr", L"KrkrLoader", MB_OK);
	}

	return result;
}


int WINAPI HookWideCharToMultiByte(
	_In_      UINT    CodePage,
	_In_      DWORD   dwFlags,
	_In_      LPCWSTR lpWideCharStr,
	_In_      int     cchWideChar,
	_Out_opt_ LPSTR   lpMultiByteStr,
	_In_      int     cbMultiByte,
	_In_opt_  LPCSTR  lpDefaultChar,
	_Out_opt_ LPBOOL  lpUsedDefaultChar
	)
{
	if (CodePage == CP_ACP)
	{
		WideCharToMultiByte(932, dwFlags, lpWideCharStr,
			cchWideChar, lpMultiByteStr, cbMultiByte,
			lpDefaultChar, lpUsedDefaultChar);
	}
	else
	{
		return WideCharToMultiByte(CodePage, dwFlags,
			lpWideCharStr, cchWideChar, lpMultiByteStr,
			cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	}
}


LPVOID WINAPI AllocateZeroedMemory(SIZE_T size) 
{
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

LPVOID WINAPI AllocateHeapInternal(SIZE_T size)
{
	return HeapAlloc(GetProcessHeap(), 0, size);
}

VOID WINAPI FreeStringInternal(LPVOID pBuffer)
{
	HeapFree(GetProcessHeap(), 0, pBuffer);
}

LPCWSTR WINAPI MultiByteToWideCharInternal(LPCSTR lpString)
{
	int size = lstrlenA(lpString)/* size without '\0' */, n = 0;
	LPWSTR wstr = (LPWSTR)AllocateHeapInternal((size + 1) << 1);
	if (wstr)
	{
		n = MultiByteToWideChar(932, 0, lpString, size, wstr, size);
		wstr[n] = L'\0';
	}
	return wstr;
}


BOOL WINAPI HookGetMenuItemInfo(HMENU hMenu, UINT uItem, BOOL fByPosition, LPMENUITEMINFOA lpmii)
{
	DWORD cchtmp = 0;
	MENUITEMINFOW miitmp;
	RtlCopyMemory(&miitmp, lpmii, lpmii->cbSize);
	if (((miitmp.fMask & MIIM_TYPE) && miitmp.fType != 0) || (miitmp.fMask & MIIM_STRING) || miitmp.cch > 0) 
	{
		cchtmp = miitmp.cch;
		miitmp.dwTypeData = (LPWSTR)AllocateZeroedMemory((cchtmp + 1) * sizeof(wchar_t));
	}

	BOOL ret = GetMenuItemInfoW(hMenu, uItem, fByPosition, &miitmp);
	if (ret)
	{
		RtlCopyMemory(lpmii, &miitmp, miitmp.cbSize);
	}
	if (cchtmp > 0) 
	{
		int cch = WideCharToMultiByte(932, 0, miitmp.dwTypeData, -1, lpmii->dwTypeData, lpmii->cch, NULL, NULL);
		if (cch > 0)
		{
			lpmii->cch = cch - 1;
		}
		if (miitmp.dwTypeData)
		{
			FreeStringInternal(miitmp.dwTypeData);
		}
		lpmii->dwTypeData[cchtmp - 1] = '\0';
	}
	return ret;
}


BOOL WINAPI HookSetMenuItemInfo(HMENU hMenu, UINT uItem, BOOL fByPosition, LPMENUITEMINFOA lpmii) 
{
	LPCSTR dwTypeDataA = NULL;
	if (((lpmii->fMask & MIIM_TYPE) && lpmii->fType != 0) || (lpmii->fMask & MIIM_STRING) || lpmii->cch > 0)
	{
		dwTypeDataA = lpmii->dwTypeData;
		lpmii->dwTypeData = (LPSTR)MultiByteToWideCharInternal(lpmii->dwTypeData);
	}
	BOOL ret = SetMenuItemInfoW(hMenu, uItem, fByPosition, (LPMENUITEMINFOW)lpmii);
	if (dwTypeDataA) 
	{
		FreeStringInternal((LPVOID)lpmii->dwTypeData);
		lpmii->dwTypeData = (LPSTR)dwTypeDataA;
	}
	return ret;
}

UINT WINAPI HookGetACP()
{
	return 932;
}


VOID WINAPI RunInlineLocale()
{
	HMODULE hModule = GetModuleHandle(NULL);

	//Some corporation disabled this exported function.(Some krkrz-based game)
	*(FARPROC *)&pfTVPGetFunctionExporter = GetProcAddress(hModule, "TVPGetFunctionExporter");

	//Krkr2 & normal Krkrz Module
	if (pfTVPGetFunctionExporter != nullptr)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID*)&pfTVPGetFunctionExporter, HookTVPGetFunctionExporter);
		DetourTransactionCommit();

		//HookWideCharToMultiByte
		//Useless
		//FARPROC pfWideCharToMultiByte = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "WideCharToMultiByte");
		//IATPatch("Kernel32.dll", pfWideCharToMultiByte, (PROC)HookWideCharToMultiByte);

		FARPROC pfSetMenuItemInfo = GetProcAddress(GetModuleHandleW(L"User32.dll"), "SetMenuItemInfoA");
		FARPROC pfGetMenuItemInfo = GetProcAddress(GetModuleHandleW(L"User32.dll"), "GetMenuItemInfoA");
		FARPROC pfGetACP = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "GetACP");

		IATPatch("User32.dll", pfSetMenuItemInfo, (PROC)HookSetMenuItemInfo);
		IATPatch("User32.dll", pfGetMenuItemInfo, (PROC)HookGetMenuItemInfo);
		IATPatch("Kernel32.dll", pfGetACP, (PROC)HookGetACP);
	}
}
