#ifndef _Xmoe_Krkr_
#define _Xmoe_Krkr_

#include <Windows.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")

HRESULT WINAPI InitHook();
HRESULT WINAPI UnInitHook();



#endif
