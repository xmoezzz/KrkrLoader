#ifndef _xmoeLocale_
#define _xmoeLocale_

#include <Windows.h>
#include <wchar.h>
#include "SecondHook.h"
#include <ntstatus.h>
#include "IATProc.h"

#define PtrOffset(e, structTest) (DWORD)&(((structTest*)0)->e)
#define IS_ATOM(_class) ((((ULONG)(_class)) & 0xFFFF0000) == 0)
#define INLINE_MIN(a, b) a < b ? a : b
#define CheckPointer(ptr) if(ptr)

VOID WINAPI RunInlineLocale();
VOID WINAPI Init2ndHook();

#pragma comment(lib, "ntdll.lib")


EXTERN_C
{
	__declspec(dllimport)
	UINT32
	NTAPI
	RtlMultiByteToUnicodeN(
	__out_bcount_part(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
	__in ULONG MaxBytesInUnicodeString,
	__out_opt PULONG BytesInUnicodeString,
	__in_bcount(BytesInMultiByteString) const CHAR *MultiByteString,
	__in ULONG BytesInMultiByteString
	);

	__declspec(dllimport)
		UINT32
		NTAPI
		RtlUnicodeToMultiByteN(
		__out_bcount_part(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
		__in ULONG MaxBytesInMultiByteString,
		__out_opt PULONG BytesInMultiByteString,
		__in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
		__in ULONG BytesInUnicodeString
		);

	__declspec(dllimport)
		BOOLEAN
		NTAPI
		RtlFreeHeap(
		__in PVOID HeapHandle,
		__in_opt ULONG Flags,
		__in __post_invalid  PVOID BaseAddress
		);


	__declspec(dllimport)
		PVOID
		NTAPI
		RtlAllocateHeap(
		__in PVOID HeapHandle,
		__in_opt ULONG Flags,
		__in SIZE_T Size
		);

}

#endif
