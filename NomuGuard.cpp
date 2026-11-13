#include "NomuGuard.h"
#include <random>
#include <map>
#include <cstring>
#include <cstdint>
#include <intrin.h>

// ============================================================================
//  ntdll layer
//  - ntdll base is found by walking PEB->Ldr (no GetModuleHandle)
//  - exports are found by hashing PE export names (no plain strings in binary)
//  - all memory operations go through Nt*/Rtl* instead of kernel32 Virtual*
// ============================================================================

namespace
{
	using NgNtStatus = LONG;
	inline bool NgSuccess(NgNtStatus status) { return status >= 0; }

	// NtCurrentProcess() pseudo handle, same value GetCurrentProcess() returns
	const HANDLE kCurrentProcess = (HANDLE)(LONG_PTR)-1;
	constexpr ULONG kMemoryBasicInformation = 0;

	using NtAllocateVirtualMemory_t = NgNtStatus(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	using NtProtectVirtualMemory_t = NgNtStatus(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	using NtQueryVirtualMemory_t = NgNtStatus(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
	using NtFreeVirtualMemory_t = NgNtStatus(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
	using RtlAddVectoredExceptionHandler_t = PVOID(NTAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);

	struct NtApi
	{
		NtAllocateVirtualMemory_t AllocateVirtualMemory = nullptr;
		NtProtectVirtualMemory_t ProtectVirtualMemory = nullptr;
		NtQueryVirtualMemory_t QueryVirtualMemory = nullptr;
		NtFreeVirtualMemory_t FreeVirtualMemory = nullptr;
		RtlAddVectoredExceptionHandler_t AddVectoredExceptionHandler = nullptr;
	};

	NtApi g_nt;

	// Minimal PEB / loader structures (only the stable leading fields are declared)
	struct NgUnicodeString
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

	struct NgLdrEntry
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		NgUnicodeString FullDllName;
		NgUnicodeString BaseDllName;
	};

	struct NgPebLdrData
	{
		ULONG Length;
		BOOLEAN Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
	};

	struct NgPeb
	{
		BYTE Reserved1[4];
		PVOID Mutant;
		PVOID ImageBaseAddress;
		NgPebLdrData* Ldr;
	};

	NgPeb* GetPeb()
	{
#if defined(_M_X64) || defined(__x86_64__)
		return (NgPeb*)__readgsqword(0x60);
#elif defined(_M_IX86) || defined(__i386__)
		return (NgPeb*)__readfsdword(0x30);
#else
#error "NomuGuard: unsupported architecture (x86 / x64 only)"
#endif
	}

	bool EqualsIgnoreCase(const NgUnicodeString& str, const wchar_t* literal)
	{
		size_t length = str.Length / sizeof(WCHAR);
		size_t i = 0;

		for (; i < length; ++i)
		{
			wchar_t a = str.Buffer[i];
			wchar_t b = literal[i];

			if (b == L'\0')
				return false;

			if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + (L'a' - L'A'));
			if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + (L'a' - L'A'));

			if (a != b)
				return false;
		}

		return literal[i] == L'\0';
	}

	BYTE* FindNtdllBase()
	{
		NgPeb* peb = GetPeb();

		if (peb == nullptr || peb->Ldr == nullptr)
			return nullptr;

		LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;

		for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink)
		{
			NgLdrEntry* entry = CONTAINING_RECORD(cur, NgLdrEntry, InLoadOrderLinks);

			if (entry->BaseDllName.Buffer != nullptr && EqualsIgnoreCase(entry->BaseDllName, L"ntdll.dll"))
				return (BYTE*)entry->DllBase;
		}

		return nullptr;
	}

	// -----------------------------------------------------------------------
	//  Compile-time DJB2 hash – no plain function name strings in the binary
	// -----------------------------------------------------------------------

	constexpr uint32_t kDjb2Init = 5381;

	constexpr uint32_t Djb2Hash(const char* str, uint32_t hash = kDjb2Init)
	{
		return (*str == '\0') ? hash : Djb2Hash(str + 1, ((hash << 5) + hash) + (uint32_t)(unsigned char)*str);
	}

	// Runtime hash for export names read from the PE
	static uint32_t Djb2HashRuntime(const char* str)
	{
		uint32_t hash = kDjb2Init;
		while (*str)
		{
			hash = ((hash << 5) + hash) + (uint32_t)(unsigned char)*str;
			++str;
		}
		return hash;
	}

	// Pre-computed hashes (constexpr ensures compile-time evaluation)
	constexpr uint32_t kHash_NtAllocateVirtualMemory   = Djb2Hash("NtAllocateVirtualMemory");
	constexpr uint32_t kHash_NtProtectVirtualMemory     = Djb2Hash("NtProtectVirtualMemory");
	constexpr uint32_t kHash_NtQueryVirtualMemory       = Djb2Hash("NtQueryVirtualMemory");
	constexpr uint32_t kHash_NtFreeVirtualMemory        = Djb2Hash("NtFreeVirtualMemory");
	constexpr uint32_t kHash_RtlAddVectoredExceptionHandler = Djb2Hash("RtlAddVectoredExceptionHandler");

	void* FindExportByHash(BYTE* base, uint32_t targetHash)
	{
		auto dos = (IMAGE_DOS_HEADER*)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (dir.VirtualAddress == 0 || dir.Size == 0)
			return nullptr;

		auto exports = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
		auto names = (DWORD*)(base + exports->AddressOfNames);
		auto ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
		auto functions = (DWORD*)(base + exports->AddressOfFunctions);

		for (DWORD i = 0; i < exports->NumberOfNames; ++i)
		{
			const char* exportName = (const char*)(base + names[i]);

			if (Djb2HashRuntime(exportName) != targetHash)
				continue;

			WORD ordinal = ordinals[i];
			if (ordinal >= exports->NumberOfFunctions)
				return nullptr;

			DWORD rva = functions[ordinal];

			// Forwarded export (RVA points inside the export directory) -> not a real function
			if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size)
				return nullptr;

			return base + rva;
		}

		return nullptr;
	}

	bool ResolveNtApi()
	{
		BYTE* ntdll = FindNtdllBase();
		if (ntdll == nullptr)
			return false;

		g_nt.AllocateVirtualMemory = (NtAllocateVirtualMemory_t)FindExportByHash(ntdll, kHash_NtAllocateVirtualMemory);
		g_nt.ProtectVirtualMemory = (NtProtectVirtualMemory_t)FindExportByHash(ntdll, kHash_NtProtectVirtualMemory);
		g_nt.QueryVirtualMemory = (NtQueryVirtualMemory_t)FindExportByHash(ntdll, kHash_NtQueryVirtualMemory);
		g_nt.FreeVirtualMemory = (NtFreeVirtualMemory_t)FindExportByHash(ntdll, kHash_NtFreeVirtualMemory);
		g_nt.AddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)FindExportByHash(ntdll, kHash_RtlAddVectoredExceptionHandler);

		return g_nt.AllocateVirtualMemory && g_nt.ProtectVirtualMemory && g_nt.QueryVirtualMemory
			&& g_nt.FreeVirtualMemory && g_nt.AddVectoredExceptionHandler;
	}

	bool SetProtect(void* address, SIZE_T size, ULONG newProtect)
	{
		// NtProtectVirtualMemory rounds BaseAddress/RegionSize in place, so pass copies
		PVOID base = address;
		SIZE_T region = size;
		ULONG oldProtect = 0;

		return NgSuccess(g_nt.ProtectVirtualMemory(kCurrentProcess, &base, &region, newProtect, &oldProtect));
	}

	bool QueryMemory(void* address, MEMORY_BASIC_INFORMATION& mbi)
	{
		SIZE_T returned = 0;
		return NgSuccess(g_nt.QueryVirtualMemory(kCurrentProcess, address, kMemoryBasicInformation, &mbi, sizeof(mbi), &returned));
	}
}

// ============================================================================
//  Guard storage
// ============================================================================

enum class GuardType : int
{
	Int32,
	Int64,
	Float
};

struct Guard
{
	int level;
	GuardType type;
	DWORD64 xorKey;
	DWORD64 lastValue;   // last ciphertext written (shadow copy)
};

template<typename T> struct GuardTraits;
template<> struct GuardTraits<int> { using Bits = uint32_t; static constexpr GuardType type = GuardType::Int32; };
template<> struct GuardTraits<INT64> { using Bits = uint64_t; static constexpr GuardType type = GuardType::Int64; };
template<> struct GuardTraits<float> { using Bits = uint32_t; static constexpr GuardType type = GuardType::Float; };

template<typename T>
static typename GuardTraits<T>::Bits ToBits(T value)
{
	typename GuardTraits<T>::Bits bits;
	static_assert(sizeof(bits) == sizeof(value), "size mismatch");
	memcpy(&bits, &value, sizeof(bits));
	return bits;
}

template<typename T>
static T FromBits(typename GuardTraits<T>::Bits bits)
{
	T value;
	memcpy(&value, &bits, sizeof(value));
	return value;
}

static std::map<void*, Guard>* g_memoryStorage = nullptr;
static bool g_NomuGuardInit = false;
static void (*g_guardViolationCallback)() = nullptr;

// ============================================================================
//  Thread safety — SRWLOCK (no kernel32 dependency, available since Vista)
//  Resolved from ntdll alongside the other APIs.
// ============================================================================

using RtlInitializeSRWLock_t = void(NTAPI*)(PVOID);
using RtlAcquireSRWLockExclusive_t = void(NTAPI*)(PVOID);
using RtlReleaseSRWLockExclusive_t = void(NTAPI*)(PVOID);

static RtlInitializeSRWLock_t g_InitSRWLock = nullptr;
static RtlAcquireSRWLockExclusive_t g_AcquireSRWLock = nullptr;
static RtlReleaseSRWLockExclusive_t g_ReleaseSRWLock = nullptr;

// RTL_SRWLOCK is just a pointer-sized value; we store it raw
static SRWLOCK g_lock = SRWLOCK_INIT;
static bool g_lockReady = false;

constexpr uint32_t kHash_RtlInitializeSRWLock       = Djb2Hash("RtlInitializeSRWLock");
constexpr uint32_t kHash_RtlAcquireSRWLockExclusive = Djb2Hash("RtlAcquireSRWLockExclusive");
constexpr uint32_t kHash_RtlReleaseSRWLockExclusive = Djb2Hash("RtlReleaseSRWLockExclusive");

// RAII lock guard
struct NgLockGuard
{
	NgLockGuard()
	{
		if (g_lockReady)
			g_AcquireSRWLock(&g_lock);
	}

	~NgLockGuard()
	{
		if (g_lockReady)
			g_ReleaseSRWLock(&g_lock);
	}

	NgLockGuard(const NgLockGuard&) = delete;
	NgLockGuard& operator=(const NgLockGuard&) = delete;
};

// ============================================================================

static DWORD64 GenerateXORKey()
{
	static std::random_device rd;
	static std::mt19937 mt(rd());
	static std::uniform_int_distribution<DWORD64> key(0x1FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF);

	return key(mt);
}

// __forceinline eliminates InitFailure's own stack frame,
// making it harder to find via stack trace analysis (issue #6).
__forceinline static void InitFailure(void* address)
{
	uintptr_t changedAddr = (uintptr_t)address;

	while (true)
	{
		DWORD64 key = GenerateXORKey();

		volatile DWORD64* pInitFail = (DWORD64*)(changedAddr ^ key);
		*pInitFail = changedAddr;
	}
}

// ============================================================================
//  VEH — only fires callback for OUR protected addresses (issue #2)
// ============================================================================

static LONG CALLBACK GlobalExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;

	// ACCESS_VIOLATION always has at least 2 parameters:
	//   [0] = read(0) / write(1) / DEP(8)
	//   [1] = the virtual address that caused the fault
	if (pExceptionInfo->ExceptionRecord->NumberParameters < 2)
		return EXCEPTION_CONTINUE_SEARCH;

	void* faultAddr = (void*)pExceptionInfo->ExceptionRecord->ExceptionInformation[1];

	// Check if this fault address belongs to one of our guarded pages.
	// We need to check if faultAddr falls within a page that starts at
	// a registered address.  Since each guard occupies its own dedicated
	// page (checked at Protect time), we look up by AllocationBase.
	bool isOurs = false;

	if (g_memoryStorage != nullptr)
	{
		// Don't lock here — we might already hold the lock, and we don't
		// want to deadlock in an exception handler.  The map is only
		// modified under the lock by our own code, and map iteration is
		// safe as long as no concurrent modification happens — which it
		// can't, because whoever holds the lock is the one who faulted.
		for (auto& kv : *g_memoryStorage)
		{
			// Each guarded address is the AllocationBase of its own page,
			// so faultAddr in [address, address + page_size) means it's ours.
			// Page size is at least 4096 on all Windows versions.
			uintptr_t base = (uintptr_t)kv.first;
			if ((uintptr_t)faultAddr >= base && (uintptr_t)faultAddr < base + 4096)
			{
				isOurs = true;
				break;
			}
		}
	}

	if (!isOurs)
		return EXCEPTION_CONTINUE_SEARCH;

	// This IS one of our pages — someone bypassed our Read/Write API
	if (g_guardViolationCallback != nullptr)
		g_guardViolationCallback();

	return EXCEPTION_CONTINUE_SEARCH;
}

static void ProtectChecker(void* address)
{
	MEMORY_BASIC_INFORMATION mbi;

	// A failed query is treated as tampering too (e.g. a hook forcing failure to skip the check)
	if (!QueryMemory(address, mbi) || mbi.Protect != PAGE_NOACCESS)
		InitFailure(address);
}

// Protected values must live at the base of their own committed, RW, private allocation.
// This guarantees page protection changes never hit other data,
// and makes it safe for UnprotectMemory to release the allocation.
static int CheckDedicatedAllocation(void* address)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!QueryMemory(address, mbi))
		return NG_SYSCALL_FAILED;

	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE)
		return NG_NOT_DEDICATED_PAGE;

	if (mbi.AllocationBase != address || mbi.Protect != PAGE_READWRITE)
		return NG_NOT_DEDICATED_PAGE;

	return NG_OK;
}

// ============================================================================
//  Generic implementation (INT / INT64 / FLOAT share this)
// ============================================================================

template<typename T>
static int ProtectImpl(void* address, T value, int level)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	if (address == nullptr || (level != 1 && level != 2))
		return NG_INVALID_ARGUMENT;

	NgLockGuard lk;

	// Re-protecting a level 2 address would write into a NOACCESS page and crash
	if (g_memoryStorage->count(address) != 0)
		return NG_ALREADY_REGISTERED;

	int status = CheckDedicatedAllocation(address);
	if (status != NG_OK)
		return status;

	using Bits = typename GuardTraits<T>::Bits;

	DWORD64 key = GenerateXORKey();
	Bits cipher = ToBits(value) ^ (Bits)key;

	*(volatile Bits*)address = cipher;

	if (level == 2 && !SetProtect(address, sizeof(Bits), PAGE_NOACCESS))
		return NG_SYSCALL_FAILED;

	Guard& guard = (*g_memoryStorage)[address];
	guard.level = level;
	guard.type = GuardTraits<T>::type;
	guard.xorKey = key;
	guard.lastValue = cipher;

	return NG_OK;
}

template<typename T>
static int WriteImpl(void* address, T value)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	if (address == nullptr)
		return NG_INVALID_ARGUMENT;

	NgLockGuard lk;

	auto it = g_memoryStorage->find(address);
	if (it == g_memoryStorage->end())
		return NG_NOT_REGISTERED;

	Guard& guard = it->second;
	if (guard.type != GuardTraits<T>::type)
		return NG_TYPE_MISMATCH;

	using Bits = typename GuardTraits<T>::Bits;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		if (!SetProtect(address, sizeof(Bits), PAGE_READWRITE))
			return NG_SYSCALL_FAILED;
	}

	DWORD64 key = GenerateXORKey();
	Bits cipher = ToBits(value) ^ (Bits)key;

	*(volatile Bits*)address = cipher;

	guard.xorKey = key;
	guard.lastValue = cipher;

	if (guard.level == 2 && !SetProtect(address, sizeof(Bits), PAGE_NOACCESS))
		return NG_SYSCALL_FAILED;

	return NG_OK;
}

template<typename T>
static int ReadImpl(void* address, T* retAddr)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	if (address == nullptr || retAddr == nullptr)
		return NG_INVALID_ARGUMENT;

	NgLockGuard lk;

	auto it = g_memoryStorage->find(address);
	if (it == g_memoryStorage->end())
		return NG_NOT_REGISTERED;

	Guard& guard = it->second;
	if (guard.type != GuardTraits<T>::type)
		return NG_TYPE_MISMATCH;

	using Bits = typename GuardTraits<T>::Bits;

	if (guard.level == 2)
	{
		ProtectChecker(address);

		if (!SetProtect(address, sizeof(Bits), PAGE_READONLY))
			return NG_SYSCALL_FAILED;
	}

	Bits cipher = *(volatile Bits*)address;

	// Re-lock immediately to keep the readable window as short as possible
	if (guard.level == 2 && !SetProtect(address, sizeof(Bits), PAGE_NOACCESS))
		return NG_SYSCALL_FAILED;

	if (cipher != (Bits)guard.lastValue)
		InitFailure(address);

	*retAddr = FromBits<T>(cipher ^ (Bits)guard.xorKey);

	return NG_OK;
}

// ============================================================================
//  Public API
// ============================================================================

int NomuGuard::InitNomuGuard(void (*guardViolationCallback)())
{
	// Prevents re-init from swapping the callback (e.g. Init(nullptr)) or stacking VEHs
	if (g_NomuGuardInit)
		return NG_ALREADY_INITIALIZED;

	if (!ResolveNtApi())
		return NG_NTAPI_UNAVAILABLE;

	// Resolve SRWLOCK functions (also from ntdll, also by hash)
	BYTE* ntdll = FindNtdllBase();
	if (ntdll != nullptr)
	{
		g_InitSRWLock = (RtlInitializeSRWLock_t)FindExportByHash(ntdll, kHash_RtlInitializeSRWLock);
		g_AcquireSRWLock = (RtlAcquireSRWLockExclusive_t)FindExportByHash(ntdll, kHash_RtlAcquireSRWLockExclusive);
		g_ReleaseSRWLock = (RtlReleaseSRWLockExclusive_t)FindExportByHash(ntdll, kHash_RtlReleaseSRWLockExclusive);

		if (g_InitSRWLock && g_AcquireSRWLock && g_ReleaseSRWLock)
		{
			g_InitSRWLock(&g_lock);
			g_lockReady = true;
		}
	}

	if (g_memoryStorage == nullptr)
		g_memoryStorage = new std::map<void*, Guard>();

	g_guardViolationCallback = guardViolationCallback;

	if (g_nt.AddVectoredExceptionHandler(1, GlobalExceptionHandler) == nullptr)
		return NG_SYSCALL_FAILED;

	g_NomuGuardInit = true;

	return NG_OK;
}

int NomuGuard::AllocGuardMemory(void** outAddress)
{
	if (!g_NomuGuardInit)
		InitFailure(outAddress);

	if (outAddress == nullptr)
		return NG_INVALID_ARGUMENT;

	PVOID base = nullptr;
	SIZE_T size = sizeof(INT64);

	if (!NgSuccess(g_nt.AllocateVirtualMemory(kCurrentProcess, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		return NG_SYSCALL_FAILED;

	*outAddress = base;

	return NG_OK;
}

int NomuGuard::UnprotectMemory(void* address)
{
	if (!g_NomuGuardInit)
		InitFailure(address);

	if (address == nullptr)
		return NG_INVALID_ARGUMENT;

	NgLockGuard lk;

	// Only addresses that passed CheckDedicatedAllocation can be released here
	auto it = g_memoryStorage->find(address);
	if (it == g_memoryStorage->end())
		return NG_NOT_REGISTERED;

	// If level 2, restore to RW before free (some NT versions reject MEM_RELEASE on NOACCESS)
	if (it->second.level == 2)
	{
		SetProtect(address, sizeof(DWORD64), PAGE_READWRITE);
	}

	PVOID base = address;
	SIZE_T size = 0;

	if (!NgSuccess(g_nt.FreeVirtualMemory(kCurrentProcess, &base, &size, MEM_RELEASE)))
		return NG_SYSCALL_FAILED;

	g_memoryStorage->erase(it);

	return NG_OK;
}

int NomuGuard::ProtectMemoryINT(void* address, int value, int level) { return ProtectImpl<int>(address, value, level); }
int NomuGuard::WriteMemoryINT(void* address, int value) { return WriteImpl<int>(address, value); }
int NomuGuard::ReadMemoryINT(void* address, int* retAddr) { return ReadImpl<int>(address, retAddr); }

int NomuGuard::ProtectMemoryINT64(void* address, INT64 value, int level) { return ProtectImpl<INT64>(address, value, level); }
int NomuGuard::WriteMemoryINT64(void* address, INT64 value) { return WriteImpl<INT64>(address, value); }
int NomuGuard::ReadMemoryINT64(void* address, INT64* retAddr) { return ReadImpl<INT64>(address, retAddr); }

int NomuGuard::ProtectMemoryFLOAT(void* address, float value, int level) { return ProtectImpl<float>(address, value, level); }
int NomuGuard::WriteMemoryFLOAT(void* address, float value) { return WriteImpl<float>(address, value); }
int NomuGuard::ReadMemoryFLOAT(void* address, float* retAddr) { return ReadImpl<float>(address, retAddr); }

extern "C"
{
	__declspec(dllexport) int Init(void (*callback)())
	{
		return NomuGuard::InitNomuGuard(callback);
	}

	__declspec(dllexport) int AllocGuardMemory(void** outAddress)
	{
		return NomuGuard::AllocGuardMemory(outAddress);
	}

	__declspec(dllexport) int UnprotectMemory(void* address)
	{
		return NomuGuard::UnprotectMemory(address);
	}

	//==============================Int==================================
	__declspec(dllexport) int ProtectMemoryINT(void* address, int value, int level)
	{
		return NomuGuard::ProtectMemoryINT(address, value, level);
	}

	__declspec(dllexport) int WriteMemoryINT(void* address, int value)
	{
		return NomuGuard::WriteMemoryINT(address, value);
	}

	__declspec(dllexport) int ReadMemoryINT(void* address, int* retAddr)
	{
		return NomuGuard::ReadMemoryINT(address, retAddr);
	}
	//==============================Int==================================


	//==============================Int64==================================
	__declspec(dllexport) int ProtectMemoryINT64(void* address, INT64 value, int level)
	{
		return NomuGuard::ProtectMemoryINT64(address, value, level);
	}

	__declspec(dllexport) int WriteMemoryINT64(void* address, INT64 value)
	{
		return NomuGuard::WriteMemoryINT64(address, value);
	}

	__declspec(dllexport) int ReadMemoryINT64(void* address, INT64* retAddr)
	{
		return NomuGuard::ReadMemoryINT64(address, retAddr);
	}
	//==============================Int64==================================


	//==============================Float==================================
	__declspec(dllexport) int ProtectMemoryFLOAT(void* address, float value, int level)
	{
		return NomuGuard::ProtectMemoryFLOAT(address, value, level);
	}

	__declspec(dllexport) int WriteMemoryFLOAT(void* address, float value)
	{
		return NomuGuard::WriteMemoryFLOAT(address, value);
	}

	__declspec(dllexport) int ReadMemoryFLOAT(void* address, float* retAddr)
	{
		return NomuGuard::ReadMemoryFLOAT(address, retAddr);
	}
	//==============================Float==================================
}
