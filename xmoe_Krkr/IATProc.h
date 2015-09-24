#ifndef _IATProc_
#define _IATProc_

#include <Windows.h>

BOOL IATPatch(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew);
BOOL IATFinder(LPCSTR szDllName, PROC pfnOrg);

#endif
