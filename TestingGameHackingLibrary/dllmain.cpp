// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <array> 
#include <Windows.h>
#include <winternl.h>
#include "GameHackingLibrary.h"
#include <dbghelp.h>
#include <tlhelp32.h>
g_infos infos;

typedef struct DPEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} DPEB_LDR_DATA, * DPPEB_LDR_DATA;

typedef struct DLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} DLDR_DATA_TABLE_ENTRY, * DPLDR_DATA_TABLE_ENTRY;\

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,				// MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation,		// MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation,	// UNICODE_STRING
    MemoryRegionInformation,			// MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation,		// MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation,		// MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation,				// MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,		// since REDSTONE3
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  UniqueProcessId;
    HANDLE                  InheritedFromProcessId;
    ULONG					HandleCount;
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;



typedef NTSTATUS(NTAPI* p_NtCreateFile)(
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

p_NtCreateFile ptr = nullptr;

// ntdll.NtReadVirtualMemory, hiding memory
typedef NTSTATUS(WINAPI* p_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded
    );

p_NtReadVirtualMemory g_NtReadVirtualMemory = nullptr;

NTSTATUS NtReadVirtualMemory_Hook(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded)
{
    std::cout << std::hex << (DWORD64)BaseAddress << "  ---   " << ProcessHandle << "  ---  " 
        << NumberOfBytesToRead <<std::endl;
    g_NtReadVirtualMemory = (p_NtReadVirtualMemory)GetProcAddress(infos.ntdllHandelCopy, "NtReadVirtualMemory");
return(g_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded));
}

typedef NTSTATUS(NTAPI* p_NtQueryVirtualMemory)(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
    );

p_NtQueryVirtualMemory g_NtQueryVirtualMemory = nullptr;

NTSTATUS 
NtQueryVirtualMemory_Hook(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength)
{
    std::cout << std::hex << (DWORD64)BaseAddress << "  ---   " << ProcessHandle << std::endl;
    g_NtQueryVirtualMemory = (p_NtQueryVirtualMemory)GetProcAddress(infos.ntdllHandelCopy, "NtQueryVirtualMemory");
    return (g_NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength));
}

typedef NTSTATUS(NTAPI* p_NtQueryInformationProcess)
(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

p_NtQueryInformationProcess g_NtQueryInformationProcess = nullptr;

NTSTATUS NtQueryInformationProcess_Hooked
(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
)
{
    std::cout << std::hex << ProcessHandle << std::endl;
    g_NtQueryInformationProcess = (p_NtQueryInformationProcess)GetProcAddress(infos.ntdllHandelCopy, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION ProcInf;
    //g_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, &ProcInf, sizeof(ProcInf), 0);
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY head;
    head = peb->Ldr->InMemoryOrderModuleList;
    return(0xC0000136);
}

void    x64_detour(DWORD64* target, DWORD64 hook);
// Define a type for the NtQuerySystemInformation function

void    unlinkModules()
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    DPPEB_LDR_DATA  loaderData = (DPPEB_LDR_DATA)peb->Ldr;

    DPLDR_DATA_TABLE_ENTRY entryMem = (DPLDR_DATA_TABLE_ENTRY)loaderData->InMemoryOrderModuleList.Flink;
    DPLDR_DATA_TABLE_ENTRY entryOrder = (DPLDR_DATA_TABLE_ENTRY)loaderData->InLoadOrderModuleList.Flink;
    DPLDR_DATA_TABLE_ENTRY entryInit = (DPLDR_DATA_TABLE_ENTRY)loaderData->InInitializationOrderModuleList.Flink;

    //while (entryMem != nullptr && entryMem->DllBase != NULL)
    //{
    //    std::cout << entryMem->BaseDllName.Buffer << std::endl;
    //    if (wcscmp(entryMem->BaseDllName.Buffer, L"ntdll_cpy.dll") == 0
    //        || wcscmp(entryMem->BaseDllName.Buffer, L"TestingGameHackingLibrary.dll") == 0)
    //    {
    //        entryMem->InMemoryOrderLinks.Blink->Flink = entryMem->InMemoryOrderLinks.Flink;
    //        entryMem->InMemoryOrderLinks.Flink->Blink = entryMem->InMemoryOrderLinks.Blink;
    //    }
    //    entryMem = (DPLDR_DATA_TABLE_ENTRY)entryMem->InMemoryOrderLinks.Flink;
    //}

    while (entryOrder != nullptr && entryOrder->DllBase != NULL)
    {
        if (wcscmp(entryOrder->BaseDllName.Buffer, L"ntdll_cpy.DLL") == 0
            || wcscmp(entryOrder->BaseDllName.Buffer, L"TestingGameHackingLibrary.dll") == 0)
        {
            entryOrder->InLoadOrderLinks.Blink->Flink = entryOrder->InLoadOrderLinks.Flink;
            entryOrder->InLoadOrderLinks.Flink->Blink = entryOrder->InLoadOrderLinks.Blink;
        }
        entryOrder = (DPLDR_DATA_TABLE_ENTRY)entryOrder->InLoadOrderLinks.Flink;
    }



   /* while (entryInit != nullptr && entryInit->DllBase != NULL)
    {
        std::cout << entryInit->BaseDllName.Buffer << std::endl;
        if (wcscmp(entryInit->BaseDllName.Buffer, L"ntdll_cpy.dll") == 0
            || wcscmp(entryInit->BaseDllName.Buffer, L"TestingGameHackingLibrary.dll") == 0)
        {
            entryInit->InInitializationOrderLinks.Blink->Flink = entryInit->InInitializationOrderLinks.Flink;
            entryInit->InInitializationOrderLinks.Flink->Blink = entryInit->InInitializationOrderLinks.Blink;
        }
        entryInit = (DPLDR_DATA_TABLE_ENTRY)entryInit->InMemoryOrderLinks.Flink;
    }*/
}

void    printAllModules()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);
    Process32First(snap, &procEntry);
    do
    {
        std::wcout << (wchar_t *)procEntry.szExeFile << std::endl;

    } while (Process32Next(snap,&procEntry));
}

void    hook()
{
    AllocConsole();
    FILE* fl;
    freopen_s(&fl, "CONOUT$", "w", stdout);

    CopyFile(L"C:/Windows/System32/ntdll.dll", L"C:/Windows/System32/ntdll_cpy.dll", TRUE);
    infos.procHandel = GetCurrentProcess();
    infos.procId = GetProcessId(infos.procHandel);
    HANDLE hFile;
    hFile = CreateFile(L"memory.dmp", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    infos.ntdllHandel = GetModuleHandleA("ntdll");
    infos.ntdllHandelCopy = LoadLibraryA("ntdll_cpy");
    //unlinkModules();
    //x64_detour((DWORD64*)GetProcAddress(infos.ntdllHandel, "NtQueryInformationProcess"), (DWORD64)NtQueryInformationProcess_Hooked);
    printAllModules();
}

void    x64_detour(DWORD64* target, DWORD64 hook)
{
    std::array<BYTE, 12> jmp_hook{ {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, 00000 << replaced with our function bytes
        0xFF, 0xE0                                                      // jmp rax
        } };
    *reinterpret_cast<DWORD64*>(jmp_hook.data() + 2) = hook;
    DWORD oldProt = 0;
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)target, jmp_hook.data(), jmp_hook.size(), NULL);
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), oldProt, &oldProt);
}

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



