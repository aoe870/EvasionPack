#include "stub.h"
#include "AES.h"
#include "lz4.h"
#include <iostream>
#include <sstream>
#include <string.h>

// �ϲ�data/rdata��text��, ��text�ĳɿɶ���д��ִ��
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

#define GET_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)(base))
#define GET_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((ULONG_PTR)GET_DOS_HEADER(base)->e_lfanew + (ULONG_PTR)(base)))
#define GET_FILE_HEADER(base) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(base)->FileHeader))
#define GET_OPTIONAL_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(base)->OptionalHeader))
#define GET_SECTION_HEADER( base ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(GET_NT_HEADER(base)) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((GET_NT_HEADER(base)))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32;
typedef STRING32 UNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY  InInitializationOrderLinks;	        //����ʼ��˳�򹹳ɵ�ģ�������������д�����Ϊ��
	DWORD   DllBase;				                    //��ģ��ʵ�ʼ��ص����ڴ���ĸ�λ��
	DWORD   EntryPoint;				                    //��ģ�����ڣ���ں���
	DWORD   SizeOfImage;				                //��ģ�����ڴ��еĴ�С
	UNICODE_STRING32    FullDllName;		            //����·����ģ����
	UNICODE_STRING32    BaseDllName;		            //������·����ģ����
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}UNICODE_STRING, * PUNICODE_STRING;


typedef struct tagPROCESSENTRY32or64
{
	DWORD   dwSize;
	DWORD   cntUsage;
	DWORD   th32ProcessID;          // this process
	ULONG_PTR th32DefaultHeapID;
	DWORD   th32ModuleID;           // associated exe
	DWORD   cntThreads;
	DWORD   th32ParentProcessID;    // this process's parent process
	LONG    pcPriClassBase;         // Base priority of process's threads
	DWORD   dwFlags;
#ifdef UNICODE
	WCHAR   szExeFile[MAX_PATH];    // Path
#else
	CHAR    szExeFile[MAX_PATH];    // Path
#endif // UNICODE

} PROCESSENTRY32or64, * LPPROCESSENTRY32or64;
#define TH32CS_SNAPPROCESS  0x00000002

// ����һ��ȫ�ֱ�������������
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// ���庯��
DefApiFun(GetProcAddress);
DefApiFun(LoadLibraryA);
DefApiFun(VirtualAlloc);
DefApiFun(VirtualProtect);
DefApiFun(VirtualFree);
DefApiFun(CreateWindowExA);
DefApiFun(ExitProcess);
DefApiFun(DefWindowProcA);
DefApiFun(GetStockObject);
DefApiFun(RegisterClassExA);
DefApiFun(ShowWindow);
DefApiFun(UpdateWindow);
DefApiFun(GetMessageA);
DefApiFun(TranslateMessage);
DefApiFun(DispatchMessageA);
DefApiFun(GetWindowTextA);
DefApiFun(PostQuitMessage);
DefApiFun(MessageBoxA);
DefApiFun(GetSystemInfo);
DefApiFun(GetTickCount64);
DefApiFun(GlobalMemoryStatusEx);

DefApiFun(CreateFileW)
DefApiFun(CloseHandle)
DefApiFun(GetFileAttributesW)
DefApiFun(ReadFileEx)
DefApiFun(WriteFile)
DefApiFun(DeleteFileW)

// ��ȡ��ǰ���ػ�ַ
POINTER_TYPE getcurmodule()
{
#ifdef _WIN64

	return *(POINTER_TYPE*)(__readgsqword(0x60) + 0x010);

#else _WIN32
	return *(POINTER_TYPE*)(__readfsdword(0x30) + 0x08);
#endif 
}


// ��ȡ����
POINTER_TYPE MyGetProcAddress(POINTER_TYPE Module, LPCSTR FunName)
{
	// 1. ��ȡDOSͷ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Module;
	// 2. ��ȡNTͷ
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(Module + pDos->e_lfanew);
	// 3. ��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. ��ȡ��������Ϣ�ṹ
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(Module + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	DWORD dwModOffset = pExport->Name;

	// Get Export Address Table
	PDWORD pEAT = (PDWORD)(Module + pExport->AddressOfFunctions);
	// Get Export Name Table
	PDWORD pENT = (PDWORD)(Module + pExport->AddressOfNames);
	// Get Export Index Table
	PWORD  pEIT = (PWORD)(Module + pExport->AddressOfNameOrdinals);

	for (DWORD dwOrdinal = 0; dwOrdinal < dwFunCount; dwOrdinal++)
	{
		if (!pEAT[dwOrdinal]) // Export Address offset
			continue;

		// 1. ��ȡ���
		DWORD dwID = pExport->Base + dwOrdinal;
		// 2. ��ȡ����������ַ
		ULONG_PTR dwFunAddrOffset = pEAT[dwOrdinal];

		for (DWORD dwIndex = 0; dwIndex < dwFunNameCount; dwIndex++)
		{
			// ����ű��в��Һ��������
			if (pEIT[dwIndex] == dwOrdinal)
			{
				// ��������������������Ʊ��е�����
				ULONG_PTR dwNameOffset = pENT[dwIndex];
				char* pFunName = (char*)((ULONG_PTR)Module + dwNameOffset);
				if (!strcmp(pFunName, FunName))
				{// ���ݺ������Ʒ��غ�����ַ
					return (Module + dwFunAddrOffset);
				}
			}
		}
	}
	return 0;

}

// ��ȡ kernel32.dll �Ļ�ַ
//__declspec(naked) long getkernelbase()
UCHAR* getKer32Base(void)
{
#ifdef _WIN64
	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x018);  //0x018��LDR�����PEBƫ��   �����LDR�Ļ���ַ
	UNICODE_STRING* FullName;
	HMODULE hKernel32 = NULL;
	LIST_ENTRY* pNode = NULL;
	pNode = (LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //ƫ�Ƶ�InInitializationOrderModuleList
	while (true)
	{
		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName����InInitialzationOrderModuList��ƫ��
		if (*(FullName->Buffer + 12) == '\0')
		{
			return (UCHAR*)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
			break;
		}
		pNode = pNode->Flink;
	}
	return 0;

#else _WIN32
	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB�е�ģ������ͷ
	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // ����ָ��ģ�������еĸ����ڵ�
	PCHAR pModuleStr = NULL;
	pLdrLinkTmp = *(PLDR_DATA_TABLE_ENTRY*)(*(DWORD*)(__readfsdword(0x30) + 0x0C) + 0x1c);;
	do {
		if (pLdrLinkTmp) {
			pModuleStr = (PCHAR)(pLdrLinkTmp->BaseDllName.Buffer);
			if (pModuleStr) {
				if ((pModuleStr[0] == 'K' || pModuleStr[0] == 'k') &&
					(pModuleStr[2] == 'E' || pModuleStr[2] == 'e') &&
					(pModuleStr[4] == 'R' || pModuleStr[4] == 'r') &&
					(pModuleStr[6] == 'N' || pModuleStr[6] == 'n') &&
					(pModuleStr[8] == 'E' || pModuleStr[8] == 'e') &&
					(pModuleStr[10] == 'L' || pModuleStr[10] == 'l') &&
					pModuleStr[12] == '3' &&
					pModuleStr[14] == '2' &&
					pModuleStr[16] == '.' &&
					(pModuleStr[18] == 'D' || pModuleStr[18] == 'd') &&
					(pModuleStr[20] == 'L' || pModuleStr[20] == 'l') &&
					(pModuleStr[22] == 'L' || pModuleStr[22] == 'l')
					)
				{
					return (UCHAR*)(pLdrLinkTmp->DllBase);
				}
			}
			pLdrLinkTmp = (PLDR_DATA_TABLE_ENTRY)(pLdrLinkTmp->InInitializationOrderLinks.Flink);
			continue;
		}
		break;
	} while (pLdrLinkHead != pLdrLinkTmp);

#endif 

	return 0;
}

// ��������
void XorDecryptSection()
{
	for (int iter = 0; iter <= ShareData.index; iter++) {
		DWORD OldProtect;
		auto va = ShareData.rva[iter] + getcurmodule();
		auto size = ShareData.size[iter];
		My_VirtualProtect((LPVOID)va, size, PAGE_READWRITE, &OldProtect);

		for (int i = 0; i < size; ++i) {
			((BYTE*)va)[i] ^= ShareData.key[iter];
		}

		My_VirtualProtect((LPVOID)va, size, OldProtect, &OldProtect);
	}

}

// ��ת��ԭʼ�� oep
void JmpOEP()
{
	void (*jump) ();
	jump = (void(*)(void))(ShareData.oldOep + getcurmodule());
	jump();
}


UCHAR* MyGetProcessAddress()
{
	UCHAR* dwBase = getKer32Base();
	// 1. ��ȡDOSͷ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	// 2. ��ȡNTͷ
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(dwBase + pDos->e_lfanew);
	// 3. ��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. ��ȡ��������Ϣ�ṹ
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwBase + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	DWORD dwModOffset = pExport->Name;

	// Get Export Address Table
	PDWORD pEAT = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	// Get Export Name Table
	PDWORD pENT = (PDWORD)(dwBase + pExport->AddressOfNames);
	// Get Export Index Table
	PWORD  pEIT = (PWORD)(dwBase + pExport->AddressOfNameOrdinals);

	for (DWORD dwOrdinal = 0; dwOrdinal < dwFunCount; dwOrdinal++)
	{
		if (!pEAT[dwOrdinal]) // Export Address offset
			continue;

		// 1. ��ȡ���
		DWORD dwID = pExport->Base + dwOrdinal;
		// 2. ��ȡ����������ַ
		ULONG_PTR dwFunAddrOffset = pEAT[dwOrdinal];

		for (DWORD dwIndex = 0; dwIndex < dwFunNameCount; dwIndex++)
		{
			// ����ű��в��Һ��������
			if (pEIT[dwIndex] == dwOrdinal)
			{
				// ��������������������Ʊ��е�����
				ULONG_PTR dwNameOffset = pENT[dwIndex];
				char* pFunName = (char*)((ULONG_PTR)dwBase + dwNameOffset);
				if (!strcmp(pFunName, "GetProcAddress"))
				{// ���ݺ������Ʒ��غ�����ַ
					return (dwBase + dwFunAddrOffset);
				}
			}
		}
	}
	return 0;
}


// ��ȡ��Ҫ�õ��ĺ���
void GetAPIAddr()
{
	// ���к������������ȡ
	auto Ker32Base = (POINTER_TYPE)getKer32Base();

	My_VirtualProtect = (decltype(VirtualProtect)*)MyGetProcAddress(Ker32Base, "VirtualProtect");
	My_GetProcAddress = (decltype(GetProcAddress)*)MyGetProcAddress(Ker32Base, "GetProcAddress");
	My_LoadLibraryA = (decltype(LoadLibraryA)*)MyGetProcAddress(Ker32Base, "LoadLibraryA");
	My_VirtualAlloc = (decltype(VirtualAlloc)*)MyGetProcAddress(Ker32Base, "VirtualAlloc");
	My_VirtualFree = (decltype(VirtualFree)*)MyGetProcAddress(Ker32Base, "VirtualFree");
	My_GetSystemInfo = (decltype(GetSystemInfo)*)MyGetProcAddress(Ker32Base, "GetSystemInfo");
	My_GetTickCount64 = (decltype(GetTickCount64)*)MyGetProcAddress(Ker32Base, "GetTickCount64");
	My_GlobalMemoryStatusEx = (decltype(GlobalMemoryStatusEx)*)MyGetProcAddress(Ker32Base, "GlobalMemoryStatusEx");

	My_CloseHandle = (decltype(CloseHandle)*)MyGetProcAddress(Ker32Base, "CloseHandle");
	My_GetFileAttributesW = (decltype(GetFileAttributesW)*)MyGetProcAddress(Ker32Base, "GetFileAttributesW");
	My_ReadFileEx = (decltype(ReadFileEx)*)MyGetProcAddress(Ker32Base, "ReadFileEx");
	My_WriteFile = (decltype(WriteFile)*)MyGetProcAddress(Ker32Base, "WriteFile");

	My_CreateFileW = (decltype(CreateFileW)*)MyGetProcAddress(Ker32Base, "CreateFileW");

	POINTER_TYPE huser = (POINTER_TYPE)My_LoadLibraryA("user32.dll");
	SetAPI(huser, CreateWindowExA);
	SetAPI(huser, DefWindowProcA);
	SetAPI(huser, RegisterClassExA);
	SetAPI(huser, ShowWindow);
	SetAPI(huser, UpdateWindow);
	SetAPI(huser, GetMessageA);
	SetAPI(huser, TranslateMessage);
	SetAPI(huser, DispatchMessageA);
	SetAPI(huser, GetWindowTextA);
	SetAPI(huser, PostQuitMessage);
	SetAPI(huser, MessageBoxA);

	DWORD hGdi = (DWORD)My_LoadLibraryA("gdi32.dll");
	SetAPI(hGdi, GetStockObject);

	My_DeleteFileW = (decltype(DeleteFile)*)MyGetProcAddress(Ker32Base, "DeleteFileW");

}


/// <summary>
/// 
/// </summary>
void AESDecryptAllSection()
{
	//��ȡ��ǰ����Ļ�ַ
	POINTER_TYPE dwBase = getcurmodule();
	
	CAES aes(ShareData.sEncryption.key);

	//ѭ��������������
	DWORD old = 0;
	for (int i = 0; i < ShareData.sEncryption.indix; i++)
	{

		//�õ��������ε��׵�ַ�ʹ�С
		unsigned char* pSection = (unsigned char*)ShareData.sEncryption.sEncryption[i].rva + dwBase;
		DWORD dwSectionSize = ShareData.sEncryption.sEncryption[i].size;

		//�޸���������
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//16���ֽڼ��� 
		int count = (dwSectionSize - (dwSectionSize % 16)) / 16;
		for (int idx = 0; idx < count; idx++) {
			//My_MessageBoxA(NULL, "bbbb", "", MB_OK);
			char* add = (char*)pSection + idx * 16;
			aes.InvCipher(add, 16);
		}

		//�������޸Ļ�ȥ
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}


/// <summary>
/// ɳ����
/// </summary>
/// <returns></returns>
bool  detectionSandbox() {

	//����
	SYSTEM_INFO systemInfo;
	My_GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2) {
		return false;
	}

	ULONGLONG uptime = My_GetTickCount64() / 1000;
	if (uptime < 1200) {
		return false;
	}

	//�ڴ�����
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	My_GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 1024) {
		return false;
	}

	return true;

}


void EncodeIAT() {

	POINTER_TYPE Module = getcurmodule();
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.oldImportRva);
	while (pImport->Name)
	{
		// 5 �������dll
		char* dllName = (char*)(pImport->Name + Module);
		HMODULE Mod = My_LoadLibraryA(dllName);
		// 6 ��ȡINT/IAT��ַ
		POINTER_TYPE* pInt = (POINTER_TYPE*)(pImport->OriginalFirstThunk + Module);
		POINTER_TYPE* pIat = (POINTER_TYPE*)(pImport->FirstThunk + Module);
		// ѭ������INT(��0��β
		while (*pInt)
		{
			auto Ordinal = IMAGE_SNAP_BY_ORDINAL(((PIMAGE_THUNK_DATA)pIat)->u1.Ordinal);
			if (Ordinal) {

#ifdef _WIN64
				ULONG_PTR dwFunOrdinal = Ordinal & 0x7FFFFFFFFFFFFFFF;
#else
				DWORD dwFunOrdinal = Ordinal & 0x7FFFFFFF;
#endif // DEBUG
				DWORD old;
				My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// ��д����	
				LPVOID Fun = My_GetProcAddress(Mod, (char*)dwFunOrdinal);				
				*pIat = (POINTER_TYPE)Fun;
				My_VirtualProtect(pIat, 4, old, &old);// �ָ�ԭ����
			}
			else {
				// ��ȡAPI��ַ
				IMAGE_IMPORT_BY_NAME* FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
				LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
				// ��IAT���ٵ�ַ(����ת�����ַ
				DWORD old;
				My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// ��д����			
				*pIat = (POINTER_TYPE)Fun;// ���ع��������ֶ�,ֱ�Ӹ�ֵ��*p����
				My_VirtualProtect(pIat, 4, old, &old);// �ָ�ԭ����
				//�¸�INT/IAT
			}
			
			pInt++;
			pIat++;
		}

		//��һ�������
		pImport++;
	}
}


/// <summary>
/// �ӳ�ִ��
/// </summary>
/// <returns></returns>
bool DelayRun() {

}

//�������Ƿ񱻵���(���ֱ����ԣ�����ֱ�ӿ���)
BOOL Check_ZwSetInformationObject()
{
	HANDLE v3;
	HANDLE TargetHandle;

	typedef NTSTATUS(__stdcall* NTSETINFORMATIONOBJECT)(HANDLE objhandle, int objinforClass, PVOID objinfo, ULONG Length);
	NTSETINFORMATIONOBJECT pZwSetInformationObject;

	typedef BOOL(__stdcall* SETHANDLEINFORMATION)(_In_ HANDLE hObject, _In_ DWORD dwMask, _In_ DWORD dwFlags);
	SETHANDLEINFORMATION pSetHandleInformation;

	typedef BOOL(__stdcall* DUPLICATEHANDLE)(
		_In_ HANDLE hSourceProcessHandle,
		_In_ HANDLE hSourceHandle,
		_In_ HANDLE hTargetProcessHandle,
		_Outptr_ LPHANDLE lpTargetHandle,
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwOptions
		);
	DUPLICATEHANDLE pDuplicateHandle;

	HMODULE hModule_1 = My_LoadLibraryA("kernel32.dll");
	pSetHandleInformation = (SETHANDLEINFORMATION)My_GetProcAddress(hModule_1, "SetHandleInformation");
	pDuplicateHandle = (DUPLICATEHANDLE)My_GetProcAddress(hModule_1, "DuplicateHandle");

	HMODULE hModule = My_LoadLibraryA("ntdll.dll");
	pZwSetInformationObject = (NTSETINFORMATIONOBJECT)My_GetProcAddress(hModule, "ZwSetInformationObject");

	pDuplicateHandle((HANDLE)-1, (HANDLE)-1, (HANDLE)-1, &TargetHandle, 0, 0, 0);
	pZwSetInformationObject(TargetHandle, 4, &TargetHandle, 2);
	pSetHandleInformation(TargetHandle, 2, 2);
	pDuplicateHandle((HANDLE)-1, TargetHandle, (HANDLE)-1, &v3, 0, 0, 1);
#ifdef _WIN64
	return !v3 || v3 == (HANDLE)0xCCCCCCCCCCCCCCCC;
#endif // _WIN64

	return !v3 || v3 == (HANDLE)0xCCCCCCCC;
}


//�������(Ѱ��Ŀ����̣��ɹ�����true,ʧ�ܷ���false)
bool GetProcessIdByName(TCHAR* szProcessName)
{

	typedef int(__stdcall* LSTRCMP_)(
#ifdef UNICODE
		_In_ LPCWSTR lpString1, _In_ LPCWSTR lpString2
#else
		_In_ LPCSTR lpString1, _In_ LPCSTR lpString2
#endif // UNICODE
		);
	LSTRCMP_ plstrcmpi;

	typedef HANDLE(__stdcall* CREATETOOLHELP32SNAPSHOT)(DWORD dwFlags, DWORD th32ProcessID);
	CREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot;
	typedef BOOL(__stdcall* PROCESS32FIRST)(HANDLE hSnapshot, LPPROCESSENTRY32or64 lppe);
	PROCESS32FIRST pProcess32First;
	typedef BOOL(__stdcall* PROCESS32NEXT)(HANDLE hSnapshot, LPPROCESSENTRY32or64 lppe);
	PROCESS32NEXT pProcess32Next;

	HMODULE hModule_1 = My_LoadLibraryA("kernel32.dll");
	pCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)My_GetProcAddress(hModule_1, "CreateToolhelp32Snapshot");

#ifdef UINCODE
	plstrcmpi = (LSTRCMP_)g_pfnGetProcAddress(hModule_1, "lstrcmpiW");
	pProcess32First = (PROCESS32FIRST)g_pfnGetProcAddress(hModule_1, "Process32FirstW");
	pProcess32Next = (PROCESS32NEXT)g_pfnGetProcAddress(hModule_1, "Process32NextW");

#else
	plstrcmpi = (LSTRCMP_)My_GetProcAddress(hModule_1, "lstrcmpiA");
	pProcess32First = (PROCESS32FIRST)My_GetProcAddress(hModule_1, "Process32First");
	pProcess32Next = (PROCESS32NEXT)My_GetProcAddress(hModule_1, "Process32Next");
#endif // UINCODE

	HANDLE hSnapProcess = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapProcess == NULL)
	{
		return FALSE;
	}
	PROCESSENTRY32or64 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	BOOL bRet = pProcess32First(hSnapProcess, &pe32);
	while (bRet)
	{
		if (plstrcmpi(pe32.szExeFile, szProcessName) == 0)
		{
			//g_pfnMessageBox(NULL, L"���������", L"Hello PEDIY", MB_OK);
			return TRUE;
		}
		bRet = pProcess32Next(hSnapProcess, &pe32);
	}
	return FALSE;
}


/// <summary>
/// ��ģ��ִ��
/// </summary>
/// <returns></returns>
bool AdversarialSandBox() {

	wchar_t name[] = L"tmpFile2";

	DWORD dwAttrib = My_GetFileAttributesW(name);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
		return false;
	}

	HANDLE hOpenFile = (HANDLE)My_CreateFileW(name,
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_NEW,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);
	if (hOpenFile == INVALID_HANDLE_VALUE)
	{
		hOpenFile = NULL;
		return false;
	}

	char str[] = "t     his is test";
	DWORD dwBytesWritten = 0;
	auto bErrorFlag = My_WriteFile(
		hOpenFile,           // open file handle
		str,      // start of data to write
		strlen(str),  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);


	My_CloseHandle(hOpenFile);

	hOpenFile = My_CreateFileW(name,               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
		NULL);                 // no attr. template

	if (hOpenFile == INVALID_HANDLE_VALUE)
	{

		hOpenFile = NULL;
		return false;
	}

	char   ReadBuffer[255] = { 0 };
	OVERLAPPED ol = { 0 };
	if (FALSE == My_ReadFileEx(hOpenFile, ReadBuffer, 255 - 1, &ol, NULL))
	{
		hOpenFile = NULL;
		return false;
	}

	if (ReadBuffer[3] == 0x20) {
		My_CloseHandle(hOpenFile);
		My_DeleteFileW(name);
		return true;
	}

	My_CloseHandle(hOpenFile);
	My_DeleteFileW(name);
	return false;
}


void UncompressSection() {
	// ����ѹ��λ��
	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//����ռ�
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// ��ѹ��
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*ѹ���������*/
		pBuff, /*��ѹ����������*/
		ShareData.LaterCompressSize,/*ѹ����Ĵ�С*/
		ShareData.FrontCompressSize/*ѹ��ǰ�Ĵ�С*/);

	//�޸�����
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//д��ԭʼ����
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//�ָ�����
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);
}

// �Ǵ�����ʼ����
extern "C" __declspec(dllexport) void start()
{
	GetAPIAddr();
	if (AdversarialSandBox()) {
		AESDecryptAllSection();
		//XorDecryptSection();
		EncodeIAT();
		JmpOEP();
	}
}
