#pragma once
#include <windows.h>

/*
보호할 메모리 주소는 반드시 VirtualAlloc이 사용되어야합니다.
그렇지 않으면 전역변수를 참조하는 다른 함수들과 꼬여서 반드시 충돌이 발생합니다.

예제)

VirtualAlloc을 활용한 변수 생성
int* pInput = (int*)VirtualAlloc(NULL, sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

pInput을 500으로 초기화와 동시에 보호
ProtectMemoryINT(pInput, 500);
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
