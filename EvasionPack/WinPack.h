#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include "PeOperation.h"

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

} SHAREDATA, * PSHAREDATA;

class WinPack
{
public:
	WinPack(std::string path);

	VOID SavaPeInfo(_In_ pPEInfo peinfo, PSHAREDATA dll);
private:

};

#endif // !Pack_winpack_h
