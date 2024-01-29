#pragma once
#include <Windows.h>
#include <winternl.h>
#include "structures.hpp"


typedef NTSTATUS(NTAPI* fnNtSetInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength
    );


typedef NTSTATUS(NTAPI* fnNtQueryInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryObject)(

    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(

    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );