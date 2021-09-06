#pragma once
#include <windows.h>

#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif




// �������ݽṹ��
typedef struct _SHAREDATA
{
	POINTER_TYPE rva[10] = {};// ���ܵ�rva
	long size[10] = {};// ���ܵĴ�С
	BYTE key[10] = {};// ���ܵ� key

	POINTER_TYPE oldRelocRva = 0;// ԭʼ�ض�λ��λ��
	POINTER_TYPE oldImageBase = 0;// ԭʼ���ػ�ַ
	POINTER_TYPE oldOep = 0;// ԭʼ oep
	POINTER_TYPE oldImportRva = 0;;

	POINTER_TYPE FrontCompressRva;//0
	POINTER_TYPE FrontCompressSize;//1
	POINTER_TYPE LaterCompressSize;//2

	unsigned char key1[16] = {};//AES������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

} SHAREDATA, *PSHAREDATA;

// �ض�λ��ṹ��
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};



// ����ȫ�ֺ�������
#define DefApiFun(name)\
	decltype(name)* My_##name = NULL;

// ��ȡָ��API
#define GetApiFun(mod,name)\
	decltype(name)* My_##name = (decltype(name)*)My_GetProcAddress(mod,#name)

// ��ȡָ��API
#define SetAPI(mod,name)\
		My_##name = (decltype(name)*)MyGetProcAddress(mod,#name)

