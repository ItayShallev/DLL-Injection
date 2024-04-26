#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <comdef.h>


#define DLL_FILE_NAME			"mydll.dll"

#define MAX_PATH_LENGTH			200
#define MEMORY_TO_ALLOCATE		4096

// Console colors
#define RED						"\033[31m"
#define GREEN					"\033[32m"
#define WHITE					"\033[37m"
#define CYAN					"\033[36m"


const char* PROCESS_NAME = "notepad.exe";
const LPCWSTR KERNEL_DLL_FILE_NAME = L"kernel32.dll";


DWORD getFullPathOfFile(const LPCSTR& fileName, char* buffer);
DWORD getPIDByName(const char* processName);
HANDLE getProcessHandle(const char* processName);
PVOID getProcedureAddress(const LPCTSTR& moduleName, const LPCSTR& procedureName);

PVOID allocateMemoryInProcess(const HANDLE& processHandle);
void writeToProcessMemory(const HANDLE& processHandle, const PVOID& memoryAddress, const char* bufferToWrite);

HANDLE createDLLThreadInProcess(const HANDLE& processHandle, const PVOID& loadLibraryAddress, const PVOID& memoryAddress);


int main()
{
	try
	{
		// Getting the full path of the DLL to inject
		char fullPathBuffer[MAX_PATH_LENGTH];
		const DWORD pathLen = getFullPathOfFile(DLL_FILE_NAME, fullPathBuffer);

		const PVOID loadLibraryAddress = getProcedureAddress(KERNEL_DLL_FILE_NAME, "LoadLibraryA");		// Getting the address of 'LoadLibraryA()' procedure

		HANDLE proc = getProcessHandle(PROCESS_NAME);		// Opening the remote process to DLL-inject into

		// Allocating memory inside the remote process and writing the DLL file path into it
		const PVOID memoryAddress = allocateMemoryInProcess(proc);
		writeToProcessMemory(proc, memoryAddress, fullPathBuffer);

		HANDLE hRemote = createDLLThreadInProcess(proc, loadLibraryAddress, memoryAddress);		// Creating a thread inside the remote process that will run the DLL

		// Waiting for the user to close the window that has been opened as part of the DLL-injection
		WaitForSingleObject(hRemote, INFINITE);
		CloseHandle(hRemote);
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << e.what() << "\n\n" << WHITE;
	}

	return 0;
}


/**
 * \brief				Gets the absolute path of a given file using the buffer
 * \param fileName		The file to fetch its absolute path
 * \param buffer		The buffer to return the absolute path with
 * \return				The length of the fetched absolute path
 */
DWORD getFullPathOfFile(const LPCSTR& fileName, char* buffer)
{
	return GetFullPathNameA(fileName, MAX_PATH_LENGTH, buffer, NULL);
}


/**
 * \brief					Returns the Process ID of a given process in the system
 * \param processName		The name of the process to get its ID
 * \return					The ID of the given process
 */
DWORD getPIDByName(const char* processName)
{
	// Creating a snapshot of the process list
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << RED << "Error creating snapshot: " << GetLastError() << WHITE << '\n';
		return 0;
	}

	// Initializing the process entry structure
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Get the first process information
	if (!Process32First(hSnapshot, &pe32)) {
		CloseHandle(hSnapshot);
		std::cerr << RED << "Error getting process list: " << GetLastError() << WHITE << '\n';
		return 0;
	}

	// Looping through the process list
	do {
		// Checking if the process name matches
		const WCHAR* wcharCurrentProcessName = pe32.szExeFile;
		_bstr_t charPCurrentProcessName(wcharCurrentProcessName);

		if (_stricmp(charPCurrentProcessName, processName) == 0)
		{
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);			// If the process was not found - closing the handle

	return 0;
}


/**
 * \brief					Returns an Handle to a given process in the system
 * \param processName		The name of the process to return an Handle to
 * \return					The Handle to the given process
 */
HANDLE getProcessHandle(const char* processName)
{
	const DWORD processID = getPIDByName(PROCESS_NAME);			// Getting the PID of the process

	// Checking if the process ID was found
	if (processID == 0)
	{
		const std::string errorMessage = CYAN + std::string("'") + std::string(PROCESS_NAME) + '\'' + RED " isn't open, please open it and run the program again...\n";
		throw std::runtime_error(errorMessage);
	}
	else
	{
		std::cout << CYAN << '\'' << PROCESS_NAME << '\'' << WHITE << " PID: " << processID << "\n" << WHITE;
	}
	
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
}


/**
 * \brief					Allocates memory inside the memory bound of the given process
 * \param processHandle		The Handle to the process to allocate memory in
 * \return					The address of the allocated memory
 */
PVOID allocateMemoryInProcess(const HANDLE& processHandle)
{
	PVOID memAddress = (PVOID)VirtualAllocEx(processHandle, NULL, MEMORY_TO_ALLOCATE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (memAddress == NULL)
	{
		throw std::runtime_error(RED "Error while allocating memory in the remote process: ERROR CODE " + GetLastError());
	}

	return memAddress;
}


/**
 * \brief					Returns the address of a given procedure from a given module
 * \param moduleName		The name of the module that contains the wanted procedure
 * \param procedureName		The name of the procedure to get it address
 * \return					The address of the given procedure
 */
PVOID getProcedureAddress(const LPCTSTR& moduleName, const LPCSTR& procedureName)
{
	const PVOID procedureAddress = (PVOID)GetProcAddress(GetModuleHandle(moduleName), procedureName);
	if (procedureAddress == NULL)
	{
		throw std::runtime_error(RED "Error while searching for the procedure address: ERROR CODE " + GetLastError());
	}

	return procedureAddress;
}


/**
 * \brief						Writes a given buffer into a given memory address of a given process
 * \param processHandle			The Handle of the process to write into its memory
 * \param memoryAddress			The memory address of the process to write into
 * \param bufferToWrite			The buffer to write into the given memory address
 */
void writeToProcessMemory(const HANDLE& processHandle, const PVOID& memoryAddress, const char* bufferToWrite)
{
	const BOOL check = WriteProcessMemory(processHandle, memoryAddress, bufferToWrite, strlen(bufferToWrite), NULL);
	if (check == 0)
	{
		throw std::runtime_error(RED "Error while writing DLL name to the process memory: ERROR CODE " + GetLastError());
	}
}


/**
 * \brief						Creates a thread inside a given process that runs the DLL that has been written into the given memory address inside the given process
 * \param processHandle			The Handle to the process to DLL-inject
 * \param loadLibraryAddress	The address of the 'LoadLibraryA()' procedure
 * \param memoryAddress			The memory address that contains the path to the DLL file to run
 * \return						An Handle to the new thread that runs the DLL-injection
 */
HANDLE createDLLThreadInProcess(const HANDLE& processHandle, const PVOID& loadLibraryAddress,
                                const PVOID& memoryAddress)
{
	HANDLE hRemote = CreateRemoteThread(processHandle, NULL, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), (LPVOID)memoryAddress, NULL, NULL);
	if (NULL == hRemote)
	{
		throw std::runtime_error(RED "Error while opening a remote thread at the remote process: ERROR CODE " + GetLastError());
	}

	std::cout << GREEN "Successfully DLL-injected " CYAN "'" << PROCESS_NAME << '\'' << GREEN "!\n\n" WHITE;

	return hRemote;
}
