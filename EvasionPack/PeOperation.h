#pragma once
#ifndef PACK_PeOperation_H
#define PACK_PeOperation_H
#include <Windows.h>
#include <tchar.h>
#include "Common.h"

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

}PEInfo, * pPEInfo;


class PeOperation 
{

public:
	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		AlignSize �� ȡ�����뺯��
	*����*  Returns:		���ض�������ֵ
	*����*  Parameter_1:	uSize,�������ֵ
	*����*  Parameter_2:	uSecAlignment���ļ���������ڴ������ֵ
	*����*  Parameter_3:
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	ULONG_PTR AlignSize(_In_ ULONG_PTR uSize, ULONG_PTR uSecAlignment)
	{
		//return (uSize % uSecAlignment == 0) ? uSize : (uSize - (uSize % uSecAlignment) + uSecAlignment);
		return ((uSize + uSecAlignment - 1) / uSecAlignment * uSecAlignment);
	};

public:

	/*////////////////////////////////////////////////////////////////
	*����*  FullName:	PerformBaseRelocation - �޸��ض�λ��
	*����*  Returns:	��
	*����*  Parameter:	char* buff,PE�ļ��׵�ַ(�����)
	*����*  Parameter:	DWORD Value��PE��ַ�뵱ǰ���ڴ��еĵ�ַ�Ĳ�ֵ
	*����*  Parameter:
	*����*  Parameter:
	*����*	Parameter:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	void PerformBaseRelocation(POINTER_TYPE buff, POINTER_TYPE Value);


	/*////////////////////////////////////////////////////////////////
	*����*  FullName:	RebuildImportTable - �޸�IAT��
	*����*  Returns:	�ɹ�����1��ʧ�ܷ���0
	*����*  Parameter:	char* buff��PE�ļ����ڴ��еĵ�ַ(�����)
	*����*  Parameter:
	*����*  Parameter:
	*����*  Parameter:
	*����*	Parameter:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	BOOL RebuildImportTable(POINTER_TYPE buff);

	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		GET_HEADER_DICTIONARY
	*����*  ����	:		��ȡĿ¼��ĵ�ַ
	*����*  Returns:		�ɹ��򷵻�Ҫ��ѯ������Ŀ¼����ڴ�ƫ��
	*����*  Parameter_1:	module��ģ��ĵ�ַ
	*����*  Parameter_2:	idx,Ҫ��ѯ���ű�
	*����*  Parameter_3:
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	DWORD GET_HEADER_DICTIONARY(POINTER_TYPE module, int idx);


	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		GetPEInformation_
	*����*  ����	:		��һ���ļ����������ڴ棬��ȡPE�ļ��ĸ�����Ϣ
	*����*  Returns:		�ɹ�����1��ʧ�ܷ���0
	*����*  Parameter_1:	FilePath,�ļ�·��
	*����*  Parameter_2:	pPEInfor���������,�ѵõ���PE��Ϣ��ŵ�pPEInfor�ṹ����
	*����*  Parameter_3:
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	bool GetPEInformation_(TCHAR* FilePath, _Out_ PEInformation* pPEInfor);


	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		GetPEInformation_1
	*����*  ����	:		�����ڴ�ģ�飬��ȡPE�ļ��ĸ�����Ϣ
	*����*  Returns:		�ɹ�����1��ʧ�ܷ���0
	*����*  Parameter_1:	pFilebuff��ģ��ĵ�ַ
	*����*  Parameter_2:	pPEInfor������������ѵõ���PE��Ϣ��ŵ�pPEInfor�ṹ����
	*����*  Parameter_3:	dwFileSize��ģ����ļ���С
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	bool GetPEInformation_1(char* pFilebuff, _Out_ PEInformation* pPEInfor, _In_ DWORD dwFileSize = 0);


	/*////////////////////////////////////////////////////////////////
	*����*  FullName:		addSeciton
	*����*  ����	:		����½�
	*����*  Returns:		�ɹ�����1��ʧ�ܷ���0
	*����*  Parameter_1:	pFileBuff��ģ���ַ
	*����*  Parameter_2:	AddSize��Ҫ��ӵĴ�С
	*����*  Parameter_3:	secname[8]���½����ƣ������ڰ˸��ֽ���
	*����*  Parameter_4:
	*����*	Parameter_5:
	*����*	Author:		    LCH
	*/////////////////////////////////////////////////////////////////;
	bool addSeciton(POINTER_TYPE pFileBuff, DWORD AddSize, char secname[8] = { 0 });


	/// <summary>
	/// ����PE�ļ�
	/// </summary>
	/// <param name="FileName"></param>
	/// <param name="Peinfo"></param>
	/// <returns></returns>
	BOOLEAN LoadExeFile(TCHAR* FileName, PEInformation* Peinfo);// ��ȡĿ�����

	/// <summary>
	/// �ж��Ƿ���PE�ļ�
	/// </summary>
	/// <param name=""></param>
	/// <param name=""></param>
	/// <returns></returns>
	BOOLEAN IsPEFile(POINTER_TYPE pFileBuffer);


	/// <summary>
	/// ��ȡPe�ļ���Ϣ
	/// </summary>
	/// <param name="Peinfo"></param>
	/// <returns></returns>
	BOOLEAN GetPeInfo(POINTER_TYPE Pe, PEInformation* Peinfo);

	void SaveFile(PEInformation Peinfo);


	void AddSection(POINTER_TYPE Base, POINTER_TYPE DllBase, PEInformation* Peinfo);


	PIMAGE_SECTION_HEADER GetSection(POINTER_TYPE Base, LPCSTR SectionName);


	VOID FixReloc(POINTER_TYPE Base, POINTER_TYPE DllBase);

	VOID CopySectionData(POINTER_TYPE Base, POINTER_TYPE DllBase);
};

#endif