// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <array> 
#include <Windows.h>
#include <winternl.h>

void    x64_detour(DWORD64* target, DWORD64 hook);
// Define a type for the NtQuerySystemInformation function

typedef NTSTATUS (NTAPI *p_NtCreateFile)(
             PHANDLE            FileHandle,
               ACCESS_MASK        DesiredAccess,
               POBJECT_ATTRIBUTES ObjectAttributes,
             PIO_STATUS_BLOCK   IoStatusBlock,
     PLARGE_INTEGER     AllocationSize,
              ULONG              FileAttributes,
               ULONG              ShareAccess,
               ULONG              CreateDisposition,
              ULONG              CreateOptions,
               PVOID              EaBuffer,
               ULONG              EaLength
);

p_NtCreateFile ptr = NULL;

NTSTATUS CreateFile_Hook(PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    std::cout << "Hooked" << std::endl;
    return(ptr(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength));
}

void    hook()
{
    AllocConsole();
    FILE* fl;
    freopen_s(&fl, "CONOUT$", "w", stdout);

    HMODULE hndl = GetModuleHandleA("ntdll");

    std::cout << hndl << std::endl;
    std::cout << GetProcAddress(hndl, "NtCreateFile") << std::endl;
    std::cout << (DWORD64)CreateFile_Hook << std::endl;
    x64_detour((DWORD64*)GetProcAddress(hndl, "NtCreateFile"), (DWORD64)CreateFile_Hook);
}


void    x64_detour(DWORD64* target, DWORD64 hook)
{ 
    std::cout << (DWORD64)hook << std::endl;
    std::array<BYTE, 13> jmp_hook {{
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, 00000
        0xFF, 0xE0,                                                     // jmp rax
        0x90 }};    //nop

    //*reinterpret_cast<DWORD64*>(jmp_hook.data() + 2) = hook;
    memcpy((void*)(jmp_hook.data() + 2), (void*)hook, sizeof(hook));

    
  

    DWORD oldProt = 0;
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)target, jmp_hook.data(), jmp_hook.size(), NULL);
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), oldProt, &oldProt);

}  
//std::array<uint8_t, 8 + 16> jmp_return =
  //{ {
  //        /* Original memory */
  //        0x00, 0x00, 0x00,												// +00 : mov r10,rcx					<-- (+00) Overwrite
  //        0x00, 0x00, 0x00, 0x00, 0x00,									// +03 : mov eax,<api number>			<-- (+03) Overwrite

  //        /* Return memory */
  //        0x50,															// +08 : push rax
  //        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// +09 : mov rax,0000000000000000		<-- (+11) Overwrite
  //        0x48, 0x87, 0x04, 0x24,											// +19 : xchg [rsp],rax
  //        0xC3															// +23 : ret
  //    } };

  //ReadProcessMemory(GetCurrentProcess(), (LPVOID)target, jmp_return.data(), 8, NULL);
  //reinterpret_cast<DWORD64*>(jmp_return.data() + 11) = (target + 8);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



