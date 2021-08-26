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
		LIST_ENTRY  InInitializationOrderLinks;	        //����ʼ��˳�򹹳ɵ�ģ�������������д�����Ϊ��
		DWORD   DllBase;				                    //��ģ��ʵ�ʼ��ص����ڴ���ĸ�λ��
		DWORD   EntryPoint;				                    //��ģ�����ڣ���ں���
		DWORD   SizeOfImage;				                //��ģ�����ڴ��еĴ�С
		UNICODE_STRING32    FullDllName;		            //����·����ģ����
		UNICODE_STRING32    BaseDllName;		            //������·����ģ����
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
	//��ȡkernel32.dll��ģ���ַ
	UCHAR* GetKernel32Addr();

	//��ȡGetProcessAddress�����ĵ�ַ
	UCHAR* MyGetProcessAddress();

	//��ʼ����Ϣ,�õ�����API�ĵ�ַ
	void InitInformation();

public:

	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		XorMachineCode - �������(��CPU���к���������ڽ������)
	*����*  Returns:		��
	*����*  Parameter_1:	cpuId��CPU���к�
	*����*  Parameter_2:	ulCodeOfBase,�������OEP
	*����*  Parameter_3:
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	void XorMachineCode(ULONGLONG cpuId, ULONG_PTR ulCodeOfBase);


	//�������Ƿ񱻵���(���ֱ����ԣ�����ֱ�ӿ���)
	BOOL Check_ZwSetInformationObject();

	//�������
	bool GetProcessIdByName(TCHAR* szProcessName);
};

