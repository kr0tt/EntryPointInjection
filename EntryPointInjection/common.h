#pragma once
#include <Windows.h>
#include "structs.h"

#define MODULE		L"C:\\Windows\\System32\\kernelbase.dll"

// from patch.c
BOOL PatchEntryPoint(IN LPCWSTR szModuleName, IN HANDLE hProcess, IN PVOID pShellcodeAdress);

// from enum.c
BOOL GetProcessHandle(IN LPCWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);

typedef struct _NT_API {
	_NtQuerySystemInformation	pNtQuerySystemInformation;
	_NtQueryInformationProcess	pNtQueryInformationProcess;
	_NtWriteVirtualMemory		pNtWriteVirtualMemory;
	_NtReadVirtualMemory		pNtReadVirtualMemory;
	_NtAllocateVirtualMemory	pNtAllocateVirtualMemory;
	_NtProtectVirtualMemory		pNtProtectVirtualMemory;
}NT_API, * PNT_API;