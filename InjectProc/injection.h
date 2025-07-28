#pragma once
#include <Winternl.h>
#include <string>
#include <vector>
#include <memory>
using namespace std;
BOOL FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids);
BOOL Dll_Injection(TCHAR *dll_name, TCHAR processname[]);
