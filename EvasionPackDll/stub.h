#pragma once
#include <windows.h>

#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif

// 共享数据结构体
typedef struct _SHAREDATA
{
	POINTER_TYPE OldOep = 0;// 原始 oep
	POINTER_TYPE rva[10] = {};// 加密的rva
	long size[10] = {};// 加密的大小
	BYTE key[10] = {};// 加密的 key
	long oldRelocRva = 0;// 原始重定位表位置
	long oldImageBase = 0;// 原始加载基址

	POINTER_TYPE FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//AES解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	

} SHAREDATA, *PSHAREDATA;

// 重定位项结构体
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};



// 定义全局函数变量
#define DefApiFun(name)\
	decltype(name)* My_##name = NULL;

// 获取指定API
#define GetApiFun(mod,name)\
	decltype(name)* My_##name = (decltype(name)*)My_GetProcAddress(mod,#name)

// 获取指定API
#define SetAPI(mod,name)\
		My_##name = (decltype(name)*)MyGetProcAddress(mod,#name)


typedef ULONG_PTR(WINAPI* fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI* fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef int(WINAPI* fnMessageBox)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
typedef HMODULE(WINAPI* fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef BOOL(WINAPI* fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef void(WINAPI* fnExitProcess)(_In_ UINT uExitCode);
typedef LPVOID(WINAPI* fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);


fnGetProcAddress	g_pfnGetProcAddress = NULL;
fnLoadLibraryA		g_pfnLoadLibraryA = NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA = NULL;
fnVirtualProtect	g_pfnVirtualProtect = NULL;
fnVirtualAlloc		g_pfnVirtualAlloc = NULL;
fnExitProcess		g_pfnExitProcess = NULL;
fnMessageBox		g_pfnMessageBox = NULL;