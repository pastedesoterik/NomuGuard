#pragma once
#include <windows.h>

/*
사용 예제:

	int status = NomuGuard::InitNomuGuard([이곳에 콜백함수]);
	if (status != NG_OK)
	{
		printf("Init failed: %d\n", status);
		return 1;
	}

	void* hpAddr = nullptr;
	NomuGuard::ProtectMemoryINT(hpAddr, 100, 2);

	보호가 끝나고 프로그램 종료전에 보호해제 필요
	NomuGuard::UnprotectMemory(hpAddr);
*/

// Return codes for every NomuGuard function.
// Exported as plain int so C# / Unity P/Invoke can marshal it without BOOL/bool size issues.
enum NomuGuardStatus : int
{
	NG_OK = 0,
	NG_ALREADY_INITIALIZED = 1,  // Init called twice (callback and VEH are NOT replaced)
	NG_NTAPI_UNAVAILABLE = 2,    // Could not resolve ntdll exports
	NG_INVALID_ARGUMENT = 3,     // null pointer or level not 1/2
	NG_NOT_REGISTERED = 4,       // address was never protected (or already unprotected)
	NG_ALREADY_REGISTERED = 5,   // address is already protected
	NG_TYPE_MISMATCH = 6,        // e.g. protected as INT, accessed as INT64
	NG_NOT_DEDICATED_PAGE = 7,   // address is not the base of its own committed RW private allocation
	NG_SYSCALL_FAILED = 8        // an Nt* call returned a failure NTSTATUS
};

namespace NomuGuard
{
	int InitNomuGuard(void (*guardViolationCallback)());

	// Optional helper: allocates a dedicated page that satisfies Protect*'s requirements.
	int AllocGuardMemory(void** outAddress);

	// Removes the guard AND releases the allocation (address must have been protected first).
	int UnprotectMemory(void* address);

	int ProtectMemoryINT(void* address, int value, int level);
	int WriteMemoryINT(void* address, int value);
	int ReadMemoryINT(void* address, int* retAddr);

	int ProtectMemoryINT64(void* address, INT64 value, int level);
	int WriteMemoryINT64(void* address, INT64 value);
	int ReadMemoryINT64(void* address, INT64* retAddr);

	int ProtectMemoryFLOAT(void* address, float value, int level);
	int WriteMemoryFLOAT(void* address, float value);
	int ReadMemoryFLOAT(void* address, float* retAddr);
}
