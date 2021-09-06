#include "stub.h"
#include "AES.h"
#include "lz4.h"

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



	////////////////////////////////////////////////////////////////////////////////////////////

		//ShareData.rva[1] = ShareData.rva[1] + getcurmodule();
		//My_VirtualProtect((LPVOID)ShareData.rva[1], ShareData.size[1], PAGE_READWRITE, &OldProtect);
		//// ִ�����˵�һ�����ָ��֮�� ShareData.rva ���� va ��
		//for (int i = 0; i < ShareData.size[1]; ++i)
		//	((BYTE*)ShareData.rva)[i] ^= ShareData.key[1];

		//My_VirtualProtect((LPVOID)ShareData.rva[1], ShareData.size[1], OldProtect, &OldProtect);
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
	DWORD dwBase = getcurmodule();

	CAES aes(ShareData.key1);
	//ѭ��������������
	DWORD old = 0;
	for (int i = 0; i < ShareData.index; i++)
	{
		//�õ��������ε��׵�ַ�ʹ�С
		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
		DWORD dwSectionSize = ShareData.data[i][1];

		//�޸���������
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//���ܴ����
		aes.InvCipher(pSection, dwSectionSize);
		for (int i = 0; i < dwSectionSize; ++i) {
			//pSection[i] ^= ShareData.key[1];
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

POINTER_TYPE function_Meaage(LPVOID add) {



	My_MessageBoxA(NULL, "ttttt", "ttttt", MB_OK);

	return (POINTER_TYPE)add;
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
		// 7 ѭ������INT(��0��β
		while (*pInt)// ��ָ��THUNK�ṹ��,�ڲ���������,�����ĸ��ֶ���Ч,����ʾһ����ַ����
		{
			// 8 ��ȡAPI��ַ
			IMAGE_IMPORT_BY_NAME* FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
			LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
			// 10 ��IAT���ٵ�ַ(����ת�����ַ
			DWORD old;
			My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// ��д����
			
			*pIat = (POINTER_TYPE)Fun;// ���ع��������ֶ�,ֱ�Ӹ�ֵ��*p����
			My_VirtualProtect(pIat, 4, old, &old);// �ָ�ԭ����
			// 11 �¸�INT/IAT
			pInt++;
			pIat++;
		}

		// 12 ��һ�������
		pImport++;
	}
}

/// <summary>
/// ��ģ��ִ��
/// </summary>
/// <returns></returns>
bool AdversarialSandBox() {

	wchar_t name[] = L"abdac";

	DWORD dwAttrib = My_GetFileAttributesW(name);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
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
		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
		return false;
	}

	char str[] = "t     erwrwhis is test";
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
		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
		return false;
	}

	char   ReadBuffer[255] = { 0 };
	OVERLAPPED ol = { 0 };
	if (FALSE == My_ReadFileEx(hOpenFile, ReadBuffer, 255 - 1, &ol, NULL))
	{
		hOpenFile = NULL;
		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
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

// �Ǵ�����ʼ����
extern "C" __declspec(dllexport) void start()
{
	GetAPIAddr();
	if (AdversarialSandBox()) {
		XorDecryptSection();
		//EncodeIAT();
		JmpOEP();
	}
}
