#pragma once

//�汾��
#define EvasionVersion "EvasionPack v1.0"

//��־����
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
	POINTER_TYPE rva[10] = {};// ���ܵ�rva
	long size[10] = {};// ���ܵĴ�С
	BYTE key[10] = {};// ���ܵ� key
}ENCRYPTIONINFO, * PENCRYPTIONINFO;


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

} SHAREDATA, * PSHAREDATA;

