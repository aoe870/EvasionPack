#pragma once
#include <Windows.h>

extern "C"
{
	// �������ݽṹ��
	typedef struct _SHAREDATA
	{
		long OldOep = 0;// ԭʼ oep
		long rva = 0;// ���ܵ�rva
		long size = 0;// ���ܵĴ�С
		BYTE key = 0;// ���ܵ� key
		long oldRelocRva = 0;// ԭʼ�ض�λ��λ��
		long oldImageBase = 0;// ԭʼ���ػ�ַ

		DWORD FrontCompressRva;//0
		DWORD FrontCompressSize;//1
		DWORD LaterCompressSize;//2

		unsigned char key1[16] = {};//AES������Կ
		int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
		int data[20][2];  //���ܵ�����RVA��Size	

		int index2 = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
		int data2[20][2];  //���ܵ�����RVA��Size	


		DWORD dwDataDir[20][3];  //����Ŀ¼���RVA��Size	
		DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���

		long ImportRva;

		DWORD TlsCallbackFuncRva;
		bool bIsTlsUseful;

	} SHAREDATA, * PSHAREDATA;
}
