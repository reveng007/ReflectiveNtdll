#include <windows.h>
#include <Winbase.h>
#include <iostream>
#include <string>
#include "shellcode.h"

#pragma warning(disable:4996)

using namespace std;

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} _data, key, _data2;

int main()
{

	unsigned char sSystemFunction033[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3', 0x0 };
	unsigned char sadvapi32[] = { 'a','d','v','a','p','i','3','2',0x0};

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary((LPCSTR)sadvapi32), (LPCSTR)sSystemFunction033);

	char _key[] = "alphaBetagamma";

	//Hello
	//unsigned char shellcode[] = { 0x48,0x65,0x6c,0x6c,0x6f };
	//Encrypted RC4
	//unsigned char shellcode[] = { 0x41, 0xd6, 0xaa, 0x12, 0x8e };
	unsigned int shellcode_size = sizeof(shellcode);

	PVOID buffer = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// Copy the character array to the allocated memory using memcpy.
	std::memcpy(buffer, shellcode, shellcode_size);

	//just setting null values at shellcode, cause why not 
	memset(shellcode, 0, shellcode_size);


	//Setting key values
	key.Buffer = (&_key);
	key.Length = sizeof(_key);

	//Setting shellcode in the struct for Systemfunction033
	_data.Buffer = buffer;
	_data.Length = shellcode_size;


	//Calling Systemfunction033
	SystemFunction033(&_data, &key);

	//Writing encrypted shellcode to bin file
	FILE* fp = fopen("enc_shellcode.bin", "wb");

	// Write the contents of the pvoid pointer to the file. They contents should be encrypted
	fwrite(buffer, shellcode_size, 1, fp);

	// Close the file
	fclose(fp);

	//instead if you want to print out the mem contents 
	/*
	for (unsigned int i = 0; i < _data.Length; i++)
	{
		cout << std::hex << (unsigned int)*((unsigned char*)buffer + i) << " ";
	}
	*/

	return 0;
}
