#include <Windows.h>
#include "Injection.h"
#include <TlHelp32.h>
#include <tchar.h>

using namespace std;

BOOL FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids) {
    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;

                THREADENTRY32 te = { sizeof(te) };
                if (Thread32First(hSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            tids.push_back(te.th32ThreadID);
                        }
                    } while (Thread32Next(hSnapshot, &te));
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid > 0 && !tids.empty();
}

BOOL Dll_Injection(TCHAR* dll_name, TCHAR processname[]) {
    TCHAR lpdllpath[MAX_PATH];
    GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

    DWORD processId = 0;
    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32 pe = { sizeof(pe) };
    BOOL found = FALSE;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processname) == 0) {
                processId = pe.th32ProcessID;
                found = TRUE;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    if (!found)
        return FALSE;

    SIZE_T size = wcslen(lpdllpath) * sizeof(TCHAR);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
        return FALSE;

    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath)
        return FALSE;

    if (!WriteProcessMemory(hProcess, remotePath, lpdllpath, size, nullptr))
        return FALSE;

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32)
        return FALSE;

    FARPROC loadLib = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLib)
        return FALSE;

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib),
        remotePath,
        0,
        nullptr
    );

    if (!hThread)
        return FALSE;

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, remotePath, size, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}
