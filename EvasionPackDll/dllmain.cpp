#include "stub.h"
#include "AES.h"
#include "lz4.h"
#include <iostream>
#include <sstream>
#include <string.h>

// 合并data/rdata到text段, 将text改成可读可写可执行
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
	LIST_ENTRY  InInitializationOrderLinks;	        //按初始化顺序构成的模块链表，在驱动中此链表为空
	DWORD   DllBase;				                    //该模块实际加载到了内存的哪个位置
	DWORD   EntryPoint;				                    //该模块的入口，入口函数
	DWORD   SizeOfImage;				                //该模块在内存中的大小
	UNICODE_STRING32    FullDllName;		            //包含路径的模块名
	UNICODE_STRING32    BaseDllName;		            //不包含路径的模块名
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

// 导出一个全局变量来共享数据
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// 定义函数
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

// 获取当前加载基址
POINTER_TYPE getcurmodule()
{
#ifdef _WIN64

	return *(POINTER_TYPE*)(__readgsqword(0x60) + 0x010);

#else _WIN32
	return *(POINTER_TYPE*)(__readfsdword(0x30) + 0x08);
#endif 
}


// 获取函数
POINTER_TYPE MyGetProcAddress(POINTER_TYPE Module, LPCSTR FunName)
{
	// 1. 获取DOS头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Module;
	// 2. 获取NT头
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(Module + pDos->e_lfanew);
	// 3. 获取数据目录表
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. 获取导出表信息结构
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

		// 1. 获取序号
		DWORD dwID = pExport->Base + dwOrdinal;
		// 2. 获取导出函数地址
		ULONG_PTR dwFunAddrOffset = pEAT[dwOrdinal];

		for (DWORD dwIndex = 0; dwIndex < dwFunNameCount; dwIndex++)
		{
			// 在序号表中查找函数的序号
			if (pEIT[dwIndex] == dwOrdinal)
			{
				// 根据序号索引到函数名称表中的名字
				ULONG_PTR dwNameOffset = pENT[dwIndex];
				char* pFunName = (char*)((ULONG_PTR)Module + dwNameOffset);
				if (!strcmp(pFunName, FunName))
				{// 根据函数名称返回函数地址
					return (Module + dwFunAddrOffset);
				}
			}
		}
	}
	return 0;

}

// 获取 kernel32.dll 的基址
//__declspec(naked) long getkernelbase()
UCHAR* getKer32Base(void)
{
#ifdef _WIN64
	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x018);  //0x018是LDR相对于PEB偏移   存放着LDR的基地址
	UNICODE_STRING* FullName;
	HMODULE hKernel32 = NULL;
	LIST_ENTRY* pNode = NULL;
	pNode = (LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //偏移到InInitializationOrderModuleList
	while (true)
	{
		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
		if (*(FullName->Buffer + 12) == '\0')
		{
			return (UCHAR*)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
			break;
		}
		pNode = pNode->Flink;
	}
	return 0;

#else _WIN32
	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB中的模块链表头
	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // 用来指向模块链表中的各个节点
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

// 解密区段
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

// 跳转到原始的 oep
void JmpOEP()
{
	void (*jump) ();
	jump = (void(*)(void))(ShareData.oldOep + getcurmodule());
	jump();
}


UCHAR* MyGetProcessAddress()
{
	UCHAR* dwBase = getKer32Base();
	// 1. 获取DOS头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	// 2. 获取NT头
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(dwBase + pDos->e_lfanew);
	// 3. 获取数据目录表
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. 获取导出表信息结构
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

		// 1. 获取序号
		DWORD dwID = pExport->Base + dwOrdinal;
		// 2. 获取导出函数地址
		ULONG_PTR dwFunAddrOffset = pEAT[dwOrdinal];

		for (DWORD dwIndex = 0; dwIndex < dwFunNameCount; dwIndex++)
		{
			// 在序号表中查找函数的序号
			if (pEIT[dwIndex] == dwOrdinal)
			{
				// 根据序号索引到函数名称表中的名字
				ULONG_PTR dwNameOffset = pENT[dwIndex];
				char* pFunName = (char*)((ULONG_PTR)dwBase + dwNameOffset);
				if (!strcmp(pFunName, "GetProcAddress"))
				{// 根据函数名称返回函数地址
					return (dwBase + dwFunAddrOffset);
				}
			}
		}
	}
	return 0;
}


// 获取想要用到的函数
void GetAPIAddr()
{
	// 所有函数都在这里获取
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
	//获取当前程序的基址
	POINTER_TYPE dwBase = getcurmodule();
	
	CAES aes(ShareData.sEncryption.key);

	//循环解密所有区段
	DWORD old = 0;
	for (int i = 0; i < ShareData.sEncryption.indix; i++)
	{

		//拿到所有区段的首地址和大小
		unsigned char* pSection = (unsigned char*)ShareData.sEncryption.sEncryption[i].rva + dwBase;
		DWORD dwSectionSize = ShareData.sEncryption.sEncryption[i].size;

		//修改区段属性
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//16个字节加密 
		int count = (dwSectionSize - (dwSectionSize % 16)) / 16;
		for (int idx = 0; idx < count; idx++) {
			//My_MessageBoxA(NULL, "bbbb", "", MB_OK);
			char* add = (char*)pSection + idx * 16;
			aes.InvCipher(add, 16);
		}

		//把属性修改回去
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}


/// <summary>
/// 沙箱检测
/// </summary>
/// <returns></returns>
bool  detectionSandbox() {

	//过度
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

	//内存数量
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
		// 5 加载相关dll
		char* dllName = (char*)(pImport->Name + Module);
		HMODULE Mod = My_LoadLibraryA(dllName);
		// 6 获取INT/IAT地址
		POINTER_TYPE* pInt = (POINTER_TYPE*)(pImport->OriginalFirstThunk + Module);
		POINTER_TYPE* pIat = (POINTER_TYPE*)(pImport->FirstThunk + Module);
		// 循环遍历INT(以0结尾
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
				My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// 可写属性	
				LPVOID Fun = My_GetProcAddress(Mod, (char*)dwFunOrdinal);				
				*pIat = (POINTER_TYPE)Fun;
				My_VirtualProtect(pIat, 4, old, &old);// 恢复原属性
			}
			else {
				// 获取API地址
				IMAGE_IMPORT_BY_NAME* FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
				LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
				// 向IAT填充假地址(可中转到真地址
				DWORD old;
				My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// 可写属性			
				*pIat = (POINTER_TYPE)Fun;// 不必管联合体字段,直接赋值到*p即可
				My_VirtualProtect(pIat, 4, old, &old);// 恢复原属性
				//下个INT/IAT
			}
			
			pInt++;
			pIat++;
		}

		//下一个导入表
		pImport++;
	}
}


/// <summary>
/// 延迟执行
/// </summary>
/// <returns></returns>
bool DelayRun() {

}

//检查程序是否被调试(发现被调试，程序直接卡死)
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


//反虚拟机(寻找目标进程，成功返回true,失败返回false)
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
			//g_pfnMessageBox(NULL, L"这是虚拟机", L"Hello PEDIY", MB_OK);
			return TRUE;
		}
		bRet = pProcess32Next(hSnapProcess, &pe32);
	}
	return FALSE;
}


/// <summary>
/// 反模拟执行
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
	// 待解压的位置
	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//申请空间
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 解压缩
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*压缩后的数据*/
		pBuff, /*解压出来的数据*/
		ShareData.LaterCompressSize,/*压缩后的大小*/
		ShareData.FrontCompressSize/*压缩前的大小*/);

	//修改属性
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//写入原始数据
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//恢复属性
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);
}

// 壳代码起始函数
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
