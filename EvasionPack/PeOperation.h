#pragma once
#ifndef PACKPEOPERATION_H
#define PACKPEOPERATION_H

#include <iostream>
#include <Windows.h>
#include "Common.h"
#include "ShareData.h"
#include "AllocMemory.h"

//PE�ṹ����Ϣ�ṹ��
typedef struct PEInformation
{
	POINTER_TYPE FileBase;			//�ļ����ڴ���ĵ�ַ
	POINTER_TYPE FileSize;				//�ļ���С
	POINTER_TYPE NumberOfSections;		//������Ŀ
	POINTER_TYPE SectionAlignment;		//�ڴ����
	POINTER_TYPE FileAlignment;			//�ļ�����
	POINTER_TYPE SizeofImage;			//�����С
	POINTER_TYPE SizeOfHeaders;			//ͷ��С
	POINTER_TYPE BaseOfData;			//���ݻ�ַ
	POINTER_TYPE ImageBase;				//�����ַ
	POINTER_TYPE SizeOfCode;			//����ڴ�С
	POINTER_TYPE AddressOfEntryPoint;	//OEP(RVA)��ڵ�
	POINTER_TYPE BaseOfCode;			//�����ַ
	POINTER_TYPE SizeOfOptionHeaders;	//��ѡͷ��С
	POINTER_TYPE e_lfanes;				//PE�ļ�ͷ��ַ
	IMAGE_DATA_DIRECTORY* DataDirectory;	//Ŀ¼
	PIMAGE_NT_HEADERS pNtHeader;			//Ntͷ
	PIMAGE_SECTION_HEADER pSectionHeader;	//��ͷ
	PIMAGE_OPTIONAL_HEADER OptionalHeader;	//��ѡPEͷ
}PEInfo, * pPEInfo;

class PeOperation :public AllocMemory
{
public:
	AllocMemory m_alloc;

public:

	/// <summary>
	/// �ڴ����
	/// </summary>
	/// <param name="uSize"> �����ֵ </param>
	/// <param name="ualign"> �ڴ����ֵ </param>
	/// <returns></returns>
	ULONG_PTR Alignment(_In_ ULONG_PTR uValue, ULONG_PTR uAlign);

	/// <summary>
	/// �ж��Ƿ���PE�ļ�
	/// </summary>
	/// <param name="pFileBuffer"></param>
	/// <param name="hwndDlg"></param>
	/// <returns></returns>
	BOOL IsPEFile(UCHAR* pFileBuffer, HWND hwndDlg = 0);

	/// <summary>
	/// �޸���ַ�ض�λ
	/// </summary>
	/// <param name="buff"></param>
	/// <param name="Value"></param>
	VOID PerformBaseRelocation(POINTER_TYPE buff, POINTER_TYPE Value);


	/// <summary>
	/// �޸�IAT��
	/// </summary>
	/// <param name="buff"></param>
	/// <returns></returns>
	BOOL RebuildImportTable(POINTER_TYPE buff);

	/// <summary>
	/// ����PE�ļ���ʽ
	/// </summary>
	/// <param name="FileName"></param>
	/// <returns></returns>
	BOOL LoadPeFile(LPCSTR FileName, _Out_ PEInformation* pPEInfor);

	/// <summary>
	/// ����½�
	/// </summary>
	/// <param name="pFileBuff">ģ���ַ</param>
	/// <param name="AddSize"></param>
	/// <param name="secname"></param>
	/// <returns></returns>
	BOOL addSeciton(POINTER_TYPE pFileBuff, DWORD AddSize, char secname[8] = { 0 });


	/// <summary>
	/// ��ȡĿ¼��ĵ�ַ
	/// </summary>
	/// <param name="module"></param>
	/// <param name="idx"></param>
	/// <returns></returns>
	DWORD GET_HEADER_DICTIONARY(POINTER_TYPE module, int idx);

	/// <summary>
	/// �ļ����ڴ���չ��
	/// </summary>
	/// <param name="pFileBuff"></param>
	/// <param name="FileSize"></param>
	/// <returns></returns>
	POINTER_TYPE StretchFile(POINTER_TYPE pFileBuff, DWORD FileSize);

	/// <summary>
	/// ��PE�ļ���ԭ���ļ����̴�С
	/// </summary>
	/// <param name="imgbuffer"></param>
	/// <param name="length"></param>
	/// <returns></returns>
	CHAR* ImageBuff_To_FileBuff(char* imgbuffer, DWORD length);

	/// <summary>
	/// ����PE�ṹ��Ϣ
	/// </summary>
	/// <param name="pFilebuff"></param>
	/// <param name="pPEInfor"></param>
	/// <param name="dwFileSize"></param>
	/// <returns></returns>
	BOOL GetPEInformation_1(char* pFilebuff, PEInformation* pPEInfor, DWORD dwFileSize = 0);
};

#endif // PACKPEOPERATION_H

