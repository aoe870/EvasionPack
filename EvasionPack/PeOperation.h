#pragma once
#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include "Common.h"


#ifndef PACK_PEOPERATION_H
#define PACK_PEOPERATION_H

#define PE_OPERAND_32 1001
#define PE_OPERAND_64 1002

//PE�ṹ����Ϣ�ṹ��
typedef struct PEInformation
{
	POINTER_TYPE FileBuffer;			//�ļ����ڴ���ĵ�ַ
	POINTER_TYPE FileSize;				//�ļ���С
	POINTER_TYPE e_lfanes;				//PE�ļ�ͷ��ַ
	POINTER_TYPE NumberOfSections;		//������Ŀ
	POINTER_TYPE SizeOfOptionHeaders;	//��ѡͷ��С
	POINTER_TYPE SizeOfCode;			//����ڴ�С
	POINTER_TYPE AddressOfEntryPoint;	//OEP(RVA)��ڵ�
	POINTER_TYPE BaseOfCode;			//�����ַ
	POINTER_TYPE BaseOfData;			//���ݻ�ַ
	POINTER_TYPE ImageBase;				//�����ַ
	POINTER_TYPE SectionAlignment;		//�ڴ����
	POINTER_TYPE FileAlignment;			//�ļ�����
	POINTER_TYPE SizeofImage;			//�����С
	POINTER_TYPE SizeOfHeaders;			//ͷ��С
	IMAGE_DATA_DIRECTORY* DataDirectory;	//Ŀ¼
	PIMAGE_NT_HEADERS pNtHeader;			//Ntͷ
	PIMAGE_SECTION_HEADER pSectionHeader;	//��ͷ
	PIMAGE_OPTIONAL_HEADER OptionalHeader;	//��ѡPEͷ

	int Operand;					//Ŀ������Ǽ�λ 
	std::string DefaultCode;
}PEInfo, * pPEInfo;

class PeOperation {

public:
	/// <summary>
	/// ��Pe�ļ�
	/// </summary>
	/// <param name="path"></param>
	BOOLEAN LoadPeFIle(_In_ std::string path, _Out_ pPEInfo pPEInfor);

	/// <summary>
	/// �ж��Ƿ��ǺϷ���PE�ļ��ṹ
	/// </summary>
	/// <param name="pFileBuffer"> pe�ļ��Ļ�ַ </param>
	/// <returns></returns>
	BOOLEAN IsPEFile(_Out_ UCHAR* pFileBuffer);

	/// <summary>
	/// ��ȡPe�ṹ����Ϣ
	/// </summary>
	/// <param name="pPEInfor"></param>
	VOID GetPeInfo(_In_ pPEInfo pPEInfor);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="Dllpe"></param>
	VOID AddSection(_In_ pPEInfo pPEInfor, _In_ pPEInfo Dllpe, std::string Name = ".vmp");

	/// <summary>
	/// �޸ĳ������
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="StartOffset"></param>
	VOID SetPeOEP(_In_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo);

	/// <summary>
	/// �޸��ض�λ
	/// </summary>
	VOID PerformBaseRelocation(_Out_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo);

	/// <summary>
	///  �������������
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="dllinfo"></param>
	VOID CopySectionData(_Out_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo);


	/// <summary>
	/// 
	/// </summary>
	/// <param name="pPEInfor"></param>
	VOID XorAllSection(_In_ pPEInfo pPEInfor, _Out_ PSHAREDATA data);

private:

	/// <summary>
	/// ��ȡpe�ļ���Ĭ�ϴ����
	/// </summary>
	/// <param name="FileBuffer"></param>
	/// <returns></returns>
	std::string GetPackDefaultCodeSection(CHAR* FileBuffer);


	/// <summary>
	/// �ڴ����
	/// </summary>
	/// <param name="n"></param>
	/// <param name="align"></param>
	/// <returns></returns>
	POINTER_TYPE Alignment(POINTER_TYPE n, POINTER_TYPE align)
	{
		return n % align == 0 ? n : (n / align + 1) * align;
	}

	/// <summary>
	/// ��ȡ��������Ϣ
	/// </summary>
	/// <param name="Base"></param>
	/// <param name="SectionName"></param>
	/// <returns></returns>
	PIMAGE_SECTION_HEADER GetSectionBase(POINTER_TYPE Base, LPCSTR SectionName);
	

public:
	std::string packName = ".vmp";

};

#endif // !PACK_PEOPERATION_H




