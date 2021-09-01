#pragma once
#ifndef PACK_WINPACK64_H
#define PACK_WINPACK64_H

#include <iostream>
#include <Windows.h>
#include "Common.h"

#define GET_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)(base))
#define GET_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((ULONG_PTR)GET_DOS_HEADER(base)->e_lfanew + (ULONG_PTR)(base)))
#define GET_FILE_HEADER(base) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(base)->FileHeader))
#define GET_OPTIONAL_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(base)->OptionalHeader))
#define GET_SECTION_HEADER( base ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(GET_NT_HEADER(base)) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((GET_NT_HEADER(base)))->FileHeader.SizeOfOptionalHeader   \
    ))

// �ض�λ��ṹ��
struct TypeOffsets
{
	WORD Offset : 12;
	WORD Type : 4;
};

// �������ݽṹ��
typedef struct _SHAREDATAA
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

} SHAREDATAA, * PSHAREDATAA;

class WinPack64
{

public:
	WinPack64();
	POINTER_TYPE Alignment(POINTER_TYPE n, POINTER_TYPE align);// �ļ�/�ڴ����
	PIMAGE_SECTION_HEADER GetSection(POINTER_TYPE Base, LPCSTR SectionName);// ��ȡ����ͷ��Ϣ

public:
	void LoadExeFile(LPCSTR FileName);// ��ȡĿ�����
	void AddSection(LPCSTR SectionName, LPCSTR SrcName);//���������
	void FixReloc();// �޸����ض�λ
	void SetOEP();// ��������OEP
	void CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// ��������������(���߿�����ǰ��
	void SaveFile(LPCSTR FileName);// ������ļ�
	void GetDefaultCodeSection(); //��ȡĬ�ϴ����
	void XorSection(std::string SectionName);// ����������
	void GetPackDefaultCodeSection();//��ȡ�ǵ�Ĭ�ϴ����
	bool IsFeFile();

private:
	POINTER_TYPE FileSize = 0;// �ļ���С,�����ڴ�/�����ļ�ʱ���õ�
	POINTER_TYPE FileBase = 0;// �ļ�����ַ; DWORD��Ϊ�˼��㷽��
	POINTER_TYPE DllBase = 0;// dll �ļ��ػ�ַ/ģ����
	POINTER_TYPE StartOffset = 0;// start �����Ķ���ƫ��,���ڼ�����OEP
	PSHAREDATAA ShareData = nullptr;// ���干������,��Ǵ���dll�ṩ��Ϣ(�Թ������ݵĲ�����Ҫд�ڿ�������֮ǰ)
	std::string PackDefaultCode = "";
	std::string DefaultCode = "";			//���ӿǳ���Ĭ�ϴ����
	std::string PackRelocName = ".stu_re";	//�ǵ��ض�λ���������(�ӿǺ�)
	std::string PackTestSection = ".pack";	//�ǵ�Ĭ�ϴ��������(�ӿǺ�)



};
#endif // PACK_WINPACK_H