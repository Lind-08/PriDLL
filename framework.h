#pragma once      

#include <windows.h>
#include <detours.h>
#include <winspool.h>

#include <string>

VOID CALLBACK DetourFinishHelperProcess(
    _In_ HWND,
    _In_ HINSTANCE,
    _In_ LPSTR,
    _In_ INT
);