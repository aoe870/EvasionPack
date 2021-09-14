#pragma once

//版本号
#define EvasionVersion "EvasionPack v1.0"

//日志类型
#define LOGTRPE_ERROR  0
#define LOGTYPE_OUTPUT 1


#ifdef _WIN64
#define  ReadFSTemporary(Offset)	__readgsdword(Offset)
#else _WIN32
#define  ReadFSTemporary(Offset)	__readfsdword(Offset)
#endif // DEBUG


#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif

typedef struct _ENCRYPTIONINFO
{
	POINTER_TYPE rva[10] = {};// 加密的rva
	long size[10] = {};// 加密的大小
	BYTE key[10] = {};// 加密的 key
}ENCRYPTIONINFO, * PENCRYPTIONINFO;


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

} SHAREDATA, * PSHAREDATA;

