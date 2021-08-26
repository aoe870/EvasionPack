#pragma once
#include <Windows.h>

class ReleaseCore
{
public:
	typedef ULONG_PTR(WINAPI* fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
	typedef HMODULE(WINAPI* fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
	typedef int(WINAPI* fnMessageBox)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
	typedef HMODULE(WINAPI* fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
	typedef BOOL(WINAPI* fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
	typedef void(WINAPI* fnExitProcess)(_In_ UINT uExitCode);
	typedef LPVOID(WINAPI* fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);


	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	}UNICODE_STRING, * PUNICODE_STRING;

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


	fnGetProcAddress	g_pfnGetProcAddress = NULL;
	fnLoadLibraryA		g_pfnLoadLibraryA = NULL;
	fnGetModuleHandleA	g_pfnGetModuleHandleA = NULL;
	fnVirtualProtect	g_pfnVirtualProtect = NULL;
	fnVirtualAlloc		g_pfnVirtualAlloc = NULL;
	fnExitProcess		g_pfnExitProcess = NULL;
	fnMessageBox		g_pfnMessageBox = NULL;
public:
	//获取kernel32.dll的模块基址
	UCHAR* GetKernel32Addr();

	//获取GetProcessAddress函数的地址
	UCHAR* MyGetProcessAddress();

	//初始化信息,得到常用API的地址
	void InitInformation();

public:

	/*////////////////////////////////////////////////////////////////
	*※※*  FullName:		XorMachineCode - 机器码绑定(将CPU序列号主程序入口进行亦或)
	*※※*  Returns:		无
	*※※*  Parameter_1:	cpuId，CPU序列号
	*※※*  Parameter_2:	ulCodeOfBase,主程序的OEP
	*※※*  Parameter_3:
	*※※*  Parameter_4:
	*※※*	Parameter_5:
	*※※*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	void XorMachineCode(ULONGLONG cpuId, ULONG_PTR ulCodeOfBase);


	//检查程序是否被调试(发现被调试，程序直接卡死)
	BOOL Check_ZwSetInformationObject();

	//反虚拟机
	bool GetProcessIdByName(TCHAR* szProcessName);
};

