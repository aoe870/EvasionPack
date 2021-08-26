#pragma once
#include <Windows.h>

extern "C"
{
	// 共享数据结构体
	typedef struct _SHAREDATA
	{
		long OldOep = 0;// 原始 oep
		long rva = 0;// 加密的rva
		long size = 0;// 加密的大小
		BYTE key = 0;// 加密的 key
		long oldRelocRva = 0;// 原始重定位表位置
		long oldImageBase = 0;// 原始加载基址

		DWORD FrontCompressRva;//0
		DWORD FrontCompressSize;//1
		DWORD LaterCompressSize;//2

		unsigned char key1[16] = {};//AES解密密钥
		int index = 0;			  //加密的区段数量 用的时候需要-1
		int data[20][2];  //加密的区段RVA和Size	

		int index2 = 0;			  //加密的区段数量 用的时候需要-1
		int data2[20][2];  //加密的区段RVA和Size	


		DWORD dwDataDir[20][3];  //数据目录表的RVA和Size	
		DWORD dwNumOfDataDir;	//数据目录表的个数

		long ImportRva;

		DWORD TlsCallbackFuncRva;
		bool bIsTlsUseful;

	} SHAREDATA, * PSHAREDATA;
}
