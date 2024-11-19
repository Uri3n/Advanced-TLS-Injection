#pragma once
#include <iostream>
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "defs.hpp"
#include "structures.hpp"
#include "functionPtrs.hpp"

bool AdvancedTlsInjection(
    _In_ HANDLE targetProcess,
    _In_ byte* targetModuleBase,
    _In_ void* remotePayload,
    _In_ HANDLE hWorkerFactory
);

bool WritePayloadIntoProcess(
    _In_ HANDLE hProcess,
    _In_ void* pPayload,
    _In_ size_t payloadSize,
    _Out_ void** pRemoteAddress
);