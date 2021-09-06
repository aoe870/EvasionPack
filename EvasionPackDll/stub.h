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
	POINTER_TYPE rva[10] = {};// 加密的rva
	long size[10] = {};// 加密的大小
	BYTE key[10] = {};// 加密的 key

	POINTER_TYPE oldRelocRva = 0;// 原始重定位表位置
	POINTER_TYPE oldImageBase = 0;// 原始加载基址
	POINTER_TYPE oldOep = 0;// 原始 oep
	POINTER_TYPE oldImportRva = 0;;

	POINTER_TYPE FrontCompressRva;//0
	POINTER_TYPE FrontCompressSize;//1
	POINTER_TYPE LaterCompressSize;//2

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

