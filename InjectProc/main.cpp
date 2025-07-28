#include <Windows.h>
#include "Injection.h"
#include <iostream>
#include <filesystem>
#include <atlconv.h>

int main()
{
	USES_CONVERSION;
	Dll_Injection(A2T("domeDmenu.dll"), A2T("GTA5_Enhanced.exe")); // Inject DLL into remote process
	return EXIT_SUCCESS;
}