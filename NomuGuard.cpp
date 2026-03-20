#include "NomuGuard.h"
#include <random>
#include <map>
#include <Windows.h>

struct Guard
{
	int level;
	DWORD64 xorKey;
	INT64 lastValue;
};

static std::map<void*, Guard>* g_memoryStorage = nullptr;
static bool g_NomuGuardInit = false;
static void (*g_guardViolationCallback)() = nullptr;

static DWORD64 GenerateXORKey()
{
	static std::random_device rd;
	static std::mt19937 mt(rd());
	static std::uniform_int_distribution<DWORD64> key(0x1FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF);

	return key(mt);
}

void InitFailure(void* address)
{
	uintptr_t changedAddr = (uintptr_t)address;

	while (true)
	{
		DWORD64 key = GenerateXORKey();

		volatile DWORD64* pInitFail = (DWORD64*)(changedAddr ^ key);
		*pInitFail = changedAddr;
	}
}

//PAGE_NOACCESS 예외처리
//예외자체는 얘가 감지하나, 이후 조치는 사용자에게 맡김
LONG CALLBACK GlobalExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		if (g_guardViolationCallback != nullptr)
			g_guardViolationCallback();

		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


void NomuGuard::InitNomuGuard(void (*guardViolationCallback)())
{
	if (g_memoryStorage == nullptr)
		g_memoryStorage = new std::map<void*, Guard>();

	g_guardViolationCallback = guardViolationCallback;

	AddVectoredExceptionHandler(1, GlobalExceptionHandler);

	g_NomuGuardInit = true;
}

void NomuGuard::ProtectChecker(void* address)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(address, &mbi, sizeof(mbi)))
	{
		if (mbi.Protect != PAGE_NOACCESS)
			InitFailure(address);
	}
}

void NomuGuard::UnprotectMemory(void* address)
{
	VirtualFree(address, 0, MEM_RELEASE);
	(*g_memoryStorage).erase(address);
}

void NomuGuard::ProtectMemoryINT(void* address, int value, int level)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	DWORD64 xorKey = GenerateXORKey();

	Guard& guard = (*g_memoryStorage)[address];

	guard.level = level;

	guard.xorKey = xorKey;

	*(int*)address = value ^ (int)xorKey;

	guard.lastValue = (uint32_t)(*(int*)address);

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(int), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::WriteMemoryINT(void* address, int value)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(int), PAGE_READWRITE, &oldProtect);
	}

	DWORD64 key = GenerateXORKey();
	guard.xorKey = key;

	*(int*)address = value ^ (int)key;

	guard.lastValue = (uint32_t)(*(int*)address);

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(int), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::ReadMemoryINT(void* address, int* retAddr)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(int), PAGE_READONLY, &oldProtect);
	}

	DWORD64 key = guard.xorKey;

	int decrypted = *(int*)address ^ (int)key;
	int lastValue = guard.lastValue ^ (int)key;

	if (decrypted != lastValue)
		InitFailure(address);

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(int), PAGE_NOACCESS, &oldProtect);
	}

	*retAddr = decrypted;
}


void NomuGuard::ProtectMemoryINT64(void* address, INT64 value, int level)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	DWORD64 xorKey = GenerateXORKey();

	Guard& guard = (*g_memoryStorage)[address];

	guard.level = level;

	guard.xorKey = xorKey;

	*(INT64*)address = value ^ (INT64)xorKey;

	guard.lastValue = *(INT64*)address;

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(INT64), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::WriteMemoryINT64(void* address, INT64 value)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(INT64), PAGE_READWRITE, &oldProtect);
	}

	DWORD64 key = GenerateXORKey();
	guard.xorKey = key;

	*(INT64*)address = value ^ (INT64)key;

	guard.lastValue = *(INT64*)address;

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(INT64), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::ReadMemoryINT64(void* address, INT64* retAddr)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(INT64), PAGE_READONLY, &oldProtect);
	}

	DWORD64 key = guard.xorKey;

	INT64 decrypted = *(INT64*)address ^ (INT64)key;
	INT64 lastValue = guard.lastValue ^ (INT64)key;

	if (decrypted != lastValue)
		InitFailure(address);

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(INT64), PAGE_NOACCESS, &oldProtect);
	}

	*retAddr = decrypted;
}


void NomuGuard::ProtectMemoryFLOAT(void* address, float value, int level)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	DWORD64 xorKey = GenerateXORKey();

	Guard& guard = (*g_memoryStorage)[address];

	guard.level = level;

	guard.xorKey = xorKey;

	*(DWORD*)address = *(volatile DWORD*)&value ^ (DWORD)xorKey;

	guard.lastValue = *(DWORD*)address;

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(float), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::WriteMemoryFLOAT(void* address, float value)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(float), PAGE_READWRITE, &oldProtect);
	}

	DWORD64 key = GenerateXORKey();
	guard.xorKey = key;

	*(DWORD*)address = *(volatile DWORD*)&value ^ (DWORD)key;

	guard.lastValue = *(DWORD*)address;

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(float), PAGE_NOACCESS, &oldProtect);
	}
}

void NomuGuard::ReadMemoryFLOAT(void* address, float* retAddr)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	auto it = g_memoryStorage->find(address);

	if (it == g_memoryStorage->end())
		return;

	Guard& guard = it->second;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(float), PAGE_READONLY, &oldProtect);
	}

	DWORD64 key = guard.xorKey;
	DWORD decrypted = *(volatile DWORD*)address ^ (DWORD)key;

	DWORD lastValue = guard.lastValue ^ (DWORD)key;
	if (decrypted != lastValue)
		InitFailure(address);

	if (guard.level == 2)
	{
		DWORD oldProtect;
		VirtualProtect(address, sizeof(float), PAGE_NOACCESS, &oldProtect);
	}

	*retAddr = *(float*)&decrypted;
}

extern "C"
{
	__declspec(dllexport) void Init(void (*callback)())
	{
		NomuGuard::InitNomuGuard(callback);
	}

	__declspec(dllexport) void UnprotectMemory(void* address)
	{
		NomuGuard::UnprotectMemory(address);
	}

	//==============================Int==================================
	__declspec(dllexport) void ProtectMemoryINT(void* address, int value, int level)
	{
		NomuGuard::ProtectMemoryINT(address, value, level);
	}

	__declspec(dllexport) void WriteMemoryINT(void* address, int value)
	{
		NomuGuard::WriteMemoryINT(address, value);
	}

	__declspec(dllexport) void ReadMemoryINT(void* address, int* retAddr)
	{
		NomuGuard::ReadMemoryINT(address, retAddr);
	}
	//==============================Int==================================


	//==============================Int64==================================
	__declspec(dllexport) void ProtectMemoryINT64(void* address, INT64 value, int level)
	{
		NomuGuard::ProtectMemoryINT64(address, value, level);
	}

	__declspec(dllexport) void WriteMemoryINT64(void* address, INT64 value)
	{
		NomuGuard::WriteMemoryINT64(address, value);
	}

	__declspec(dllexport) void ReadMemoryINT64(void* address, INT64* retAddr)
	{
		NomuGuard::ReadMemoryINT64(address, retAddr);
	}
	//==============================Int64==================================


	//==============================Float==================================
	__declspec(dllexport) void ProtectMemoryFLOAT(void* address, float value, int level)
	{
		NomuGuard::ProtectMemoryFLOAT(address, value, level);
	}

	__declspec(dllexport) void WriteMemoryFLOAT(void* address, float value)
	{
		NomuGuard::WriteMemoryFLOAT(address, value);
	}

	__declspec(dllexport) void ReadMemoryFLOAT(void* address, float* retAddr)
	{
		NomuGuard::ReadMemoryFLOAT(address, retAddr);
	}
	//==============================Float==================================
}