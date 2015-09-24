#ifndef _Config_
#define _Config_

#include <Windows.h>
#include <string>

using std::wstring;


bool ReadLogFile(wstring& Path, bool& CheckProcess, bool& TryHack, bool& runLE);


#endif
