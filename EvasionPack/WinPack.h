#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include "PeOperation.h"

// �������ݽṹ��
typedef struct _SHAREDATA
{
	POINTER_TYPE OldOep = 0;// ԭʼ oep
	POINTER_TYPE rva[10] = {};// ���ܵ�rva
	long size[10] = {};// ���ܵĴ�С
	BYTE key[10] = {};// ���ܵ� key

	long oldRelocRva = 0;// ԭʼ�ض�λ��λ��
	long oldImageBase = 0;// ԭʼ���ػ�ַ

	POINTER_TYPE FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//AES������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

} SHAREDATA, * PSHAREDATA;

class WinPack
{
public:
	WinPack(std::string path);

	VOID SavaPeInfo(_In_ pPEInfo peinfo, PSHAREDATA dll);
private:

};

#endif // !Pack_winpack_h
