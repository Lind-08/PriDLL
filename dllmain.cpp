#include "framework.h"

bool flag = false;

HANDLE (WINAPI *TrueCreateFileW)(
LPCWSTR               lpFileName,
DWORD                 dwDesiredAccess,
DWORD                 dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
DWORD                 dwCreationDisposition,
DWORD                 dwFlagsAndAttributes,
HANDLE                hTemplateFile) 
= CreateFileW;

HANDLE WINAPI TramplinedCreateFileW(
    LPCWSTR a0,
    DWORD a1,
    DWORD a2,
    LPSECURITY_ATTRIBUTES a3,
    DWORD a4,
    DWORD a5,
    HANDLE a6)
{
    OutputDebugStringW(L"TramplinedCreateFileW invoked");
    OutputDebugStringW((std::wstring(L"Path: ") + std::wstring(a0)).c_str());
    return TrueCreateFileW(a0,a1,a2,a3,a4,a5,a6);
}

BOOL (WINAPI *TrueEnumPrintersW)(
    DWORD   Flags,
    LPTSTR  Name,
    DWORD   Level,
    LPBYTE  pPrinterEnum,
    DWORD   cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned);

BOOL (WINAPI *TrueGetDefaultPrinterW)(
    LPTSTR  pszBuffer,
    LPDWORD pcchBuffer);

BOOL (WINAPI *TrueOpenPrinterW)(
    LPTSTR             pPrinterName,
    LPHANDLE           phPrinter,
    LPPRINTER_DEFAULTS pDefault
);

HMODULE (WINAPI *TrueLoadLibraryW)(
    LPCWSTR lpLibFileName
) = LoadLibraryW;

BOOL WINAPI TramplinedEnumPrintersW(
    DWORD   Flags,
    LPTSTR  Name,
    DWORD   Level,
    LPBYTE  pPrinterEnum,
    DWORD   cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned
)
{
    OutputDebugStringW(L"TramplinedEnumPrinters invoked");
    return TrueEnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
}

BOOL WINAPI TramplinedGetDefaultPrinterW(
    LPTSTR  pszBuffer,
    LPDWORD pcchBuffer
)
{
    OutputDebugStringW(L"TramplinedGetDefaultPrinterW invoked");
    return TrueGetDefaultPrinterW(pszBuffer, pcchBuffer);
}

BOOL WINAPI TramplinedOpenPrinterW(
    LPTSTR             pPrinterName,
    LPHANDLE           phPrinter,
    LPPRINTER_DEFAULTS pDefault
)
{
    OutputDebugStringW(L"TramplinedOpenPrinterW invoked");
    return TrueOpenPrinterW(pPrinterName, phPrinter, pDefault);
}



void AttachHooks()
{
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueGetDefaultPrinterW, TramplinedGetDefaultPrinterW);
    DetourAttach(&(PVOID&)TrueOpenPrinterW, TramplinedOpenPrinterW);
    DetourAttach(&(PVOID&)TrueEnumPrintersW, TramplinedEnumPrintersW);
    if(DetourTransactionCommit() == NO_ERROR)
    {
        OutputDebugStringW(L"GetDefaultPrinterW detoured successfully");
        OutputDebugStringW(L"OpenPrinterW detoured successfully");
        OutputDebugStringW(L"EnumPrintersW detoured successfully");
    }
}

void DetachHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueGetDefaultPrinterW, TramplinedGetDefaultPrinterW);
    DetourDetach(&(PVOID&)TrueEnumPrintersW, TramplinedEnumPrintersW);
    DetourDetach(&(PVOID&)TrueOpenPrinterW, TramplinedOpenPrinterW);
    DetourTransactionCommit();
}

HMODULE WINAPI TramplinedLoadLibraryW (
    LPCWSTR lpLibFileName
)
{
    OutputDebugStringW(L"TramplinedLoadLibraryW invoked");
    OutputDebugStringW((std::wstring(L"LibFileName: ") + std::wstring(lpLibFileName)).c_str());
    std::wstring libFileName(lpLibFileName);
    if (libFileName.find(L"winspool.drv") != std::wstring::npos)
    {
        if (!flag)
        {
            auto hModule = TrueLoadLibraryW(lpLibFileName);
            if (hModule)
            {
                TrueGetDefaultPrinterW = (BOOL (WINAPI*)(LPTSTR, LPDWORD))GetProcAddress(hModule, "GetDefaultPrinterW");
                TrueEnumPrintersW = (BOOL (WINAPI *)(DWORD, LPTSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD ))GetProcAddress(hModule, "EnumPrintersW");
                TrueOpenPrinterW = (BOOL (WINAPI *)(LPTSTR, LPHANDLE, LPPRINTER_DEFAULTS)) GetProcAddress(hModule, "OpenPrinterW");
                AttachHooks();
                flag = true;
            }
            return hModule;
        }
    }
    return TrueLoadLibraryW(lpLibFileName);
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    DisableThreadLibraryCalls(hModule);
    /*hWinspool = LoadLibraryW(L"Winspool.drv");
    if (!hWinspool)
    {
        OutputDebugStringW(L"Can't load winspool.drv");
        return TRUE;
    }

    TrueGetDefaultPrinterW = (BOOL (WINAPI*)(LPTSTR, LPDWORD))GetProcAddress(hWinspool, "GetDefaultPrinterW");
    TrueEnumPrintersW = (BOOL (WINAPI *)(DWORD, LPTSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD ))GetProcAddress(hWinspool, "EnumPrintersW");
    TrueOpenPrinterW = (BOOL (WINAPI *)(LPTSTR, LPHANDLE, LPPRINTER_DEFAULTS)) GetProcAddress(hWinspool, "OpenPrinterW");
    */
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //DetourAttach(&(PVOID&)TrueCreateFileW, TramplinedCreateFileW);
        DetourAttach(&(PVOID&)TrueLoadLibraryW, TramplinedLoadLibraryW);
        //DetourAttach(&(PVOID&)TrueGetDefaultPrinterW, TramplinedGetDefaultPrinterW);
        //DetourAttach(&(PVOID&)TrueOpenPrinterW, TramplinedOpenPrinterW);
        //DetourAttach(&(PVOID&)TrueEnumPrintersW, TramplinedEnumPrintersW);
        if(DetourTransactionCommit() == NO_ERROR)
        {
            //OutputDebugStringW(L"CreateFileW detoured successfully");
            OutputDebugStringW(L"LoadLibraryW detoured successfully");
            //OutputDebugStringW(L"GetDefaultPrinterW detoured successfully");
            //OutputDebugStringW(L"OpenPrinterW detoured successfully");
            //OutputDebugStringW(L"EnumPrintersW detoured successfully");
        }
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //DetourDetach(&(PVOID&)TrueCreateFileW, TramplinedCreateFileW);
        DetourDetach(&(PVOID&)TrueLoadLibraryW, TramplinedLoadLibraryW);
        //DetourDetach(&(PVOID&)TrueGetDefaultPrinterW, TramplinedGetDefaultPrinterW);
        //DetourDetach(&(PVOID&)TrueEnumPrintersW, TramplinedEnumPrintersW);
        //DetourDetach(&(PVOID&)TrueOpenPrinterW, TramplinedOpenPrinterW);
        DetourTransactionCommit();
        DetachHooks();
        break;
    }
    return TRUE;
}

