#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "common.h"

extern NT_API g_nt;

BOOL GetProcessHandle(IN LPCWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) { // by @NUL0x4C | @mrd0x : MalDevAcademy 

	ULONG							uReturn1 = NULL,
									uReturn2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	NTSTATUS						STATUS = NULL;
	PVOID							pFreeSystemProcInfo = NULL;

	
	if (g_nt.pNtQuerySystemInformation == NULL) {
		printf("\t[i] GetProcAddress Failed With Error: %d", GetLastError());
		return FALSE;
	}

	g_nt.pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturn1);
	// Allocate space on the heap for the SYSTEM_PROCESS_INFORMATION array
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturn1);
	if (SystemProcInfo == NULL) {
		printf("\t[i] HeapAlloc Failed With Error: %d", GetLastError());
		return FALSE;
	}

	// Will be used to free the allocated heap later
	pFreeSystemProcInfo = SystemProcInfo;

	// Get array of SYSTEM_PROCESS_INFORMATION structures for every process on the system
	STATUS = g_nt.pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturn1, &uReturn2);
	if (STATUS != 0x00) {
		printf("\t[i] NtQuerySystemInformation Failed With Error: 0x%0.8X", STATUS);
		return FALSE;
	}

	while (TRUE) {

		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcessName) == 0) {
			*dwProcessId = SystemProcInfo->UniqueProcessId;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset) {
			break;
		}
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pFreeSystemProcInfo);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	else
		return TRUE;
}