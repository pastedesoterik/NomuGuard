#pragma once
#include <Windows.h>

/*
보호할 메모리 주소는 반드시 VirtualAlloc이 사용되어야합니다.
그렇지 않으면 전역변수를 참조하는 다른 함수들과 꼬여서 반드시 충돌이 발생합니다.

예제)

VirtualAlloc을 활용한 변수 생성
int* pInput = (int*)VirtualAlloc(NULL, sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

pInput을 500으로 초기화와 동시에 보호
ProtectMemoryINT(pInput, 500);
*/


namespace NomuGuard
{
	//게임 실행시 최초 1회만 실행시켜야 하며, 매개변수로 비정상 메모리 접근이 이루어졌을시
	//실행될 코드가 들어있는 void 자료형으로 만들어진 함수를 넣어야합니다.
	void InitNomuGuard(void (*guardViolationCallback)());

	//보호된 특정 주소의 대해서 보호상태를 확인 후, 대응합니다.
	//싱글스레드에서만 사용이 권장됩니다.
	void ProtectChecker(void* address);

	//특정 메모리 주소의 보호를 해제합니다.
	//게임 종료와 같은 상황에서 한번만 호출해야합니다.
	void UnprotectMemory(void* address);


	//특정 INT 메모리 주소에 대해 PAGE_NOACCESS, 그리고 값 암호화를 진행합니다.
	//변수의 초기화때 한번만 호출해야하며, value 매개변수로 값이 초기화됩니다.
	//level에 2를 넣으면 PAGE_NOACCESS 권한이 포함되며, 2가 아니라면 값 암호화만 진행합니다.
	void ProtectMemoryINT(void* address, int value, int level);

	//INT로 되어있는 메모리의 값을 value로 수정합니다.
	//메모리가 ProtectMemoryINT로 보호가 되어있어야합니다.
	void WriteMemoryINT(void* address, int value);

	//INT로 되어있는 메모리의 값을 읽어와 retAddr의 주소에 씁니다.
	//메모리가 ProtectMemoryINT로 보호가 되어있어야합니다.
	void ReadMemoryINT(void* address, int* retAddr);


	//특정 INT64 메모리 주소에 대해 PAGE_NOACCESS, 그리고 값 암호화를 진행합니다.
	//변수의 초기화때 한번만 호출해야하며, value 매개변수로 값이 초기화됩니다.
	//level에 2를 넣으면 PAGE_NOACCESS 권한이 포함되며, 2가 아니라면 값 암호화만 진행합니다.
	void ProtectMemoryINT64(void* address, INT64 value, int level);

	//INT64로 되어있는 메모리의 값을 value로 수정합니다.
	//메모리가 ProtectMemoryINT64로 보호가 되어있어야합니다.
	void WriteMemoryINT64(void* address, INT64 value);

	//INT64로 되어있는 메모리의 값을 읽어와 retAddr의 주소에 씁니다.
	//메모리가 ProtectMemoryINT64로 보호가 되어있어야합니다.
	void ReadMemoryINT64(void* address, INT64* retAddr);
	

	//특정 FLOAT 메모리 주소에 대해 PAGE_NOACCESS, 그리고 값 암호화를 진행합니다.
	//변수의 초기화때 한번만 호출해야하며, value 매개변수로 값이 초기화됩니다.
		//level에 2를 넣으면 PAGE_NOACCESS 권한이 포함되며, 2가 아니라면 값 암호화만 진행합니다.
	void ProtectMemoryFLOAT(void* address, float value, int level);

	//FLOAT으로 되어있는 메모리의 값을 value로 수정합니다.
	//메모리가 ProtectMemoryFLOAT으로 보호가 되어있어야합니다.
	void WriteMemoryFLOAT(void* address, float value);

	//FLOAT으로 되어있는 메모리의 값을 읽어와 retAddr의 주소에 씁니다.
	//메모리가 ProtectMemoryFLOAT으로 보호가 되어있어야합니다.
	void ReadMemoryFLOAT(void* address, float* retAddr);
}