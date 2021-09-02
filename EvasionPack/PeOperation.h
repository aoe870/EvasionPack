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

//PE结构的信息结构体
typedef struct PEInformation
{
	POINTER_TYPE FileBuffer;			//文件在内存里的地址
	POINTER_TYPE FileSize;				//文件大小
	POINTER_TYPE e_lfanes;				//PE文件头地址
	POINTER_TYPE NumberOfSections;		//区段数目
	POINTER_TYPE SizeOfOptionHeaders;	//可选头大小
	POINTER_TYPE SizeOfCode;			//代码节大小
	POINTER_TYPE AddressOfEntryPoint;	//OEP(RVA)入口点
	POINTER_TYPE BaseOfCode;			//代码基址
	POINTER_TYPE BaseOfData;			//数据基址
	POINTER_TYPE ImageBase;				//镜像基址
	POINTER_TYPE SectionAlignment;		//内存对齐
	POINTER_TYPE FileAlignment;			//文件对齐
	POINTER_TYPE SizeofImage;			//镜像大小
	POINTER_TYPE SizeOfHeaders;			//头大小
	IMAGE_DATA_DIRECTORY* DataDirectory;	//目录
	PIMAGE_NT_HEADERS pNtHeader;			//Nt头
	PIMAGE_SECTION_HEADER pSectionHeader;	//节头
	PIMAGE_OPTIONAL_HEADER OptionalHeader;	//可选PE头

	int Operand;					//目标软件是几位 
	std::string DefaultCode;
}PEInfo, * pPEInfo;

class PeOperation {

public:
	/// <summary>
	/// 打开Pe文件
	/// </summary>
	/// <param name="path"></param>
	BOOLEAN LoadPeFIle(_In_ std::string path, _Out_ pPEInfo pPEInfor);

	/// <summary>
	/// 判断是否是合法的PE文件结构
	/// </summary>
	/// <param name="pFileBuffer"> pe文件的基址 </param>
	/// <returns></returns>
	BOOLEAN IsPEFile(_Out_ UCHAR* pFileBuffer);

	/// <summary>
	/// 获取Pe结构的信息
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
	/// 修改程序入口
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="StartOffset"></param>
	VOID SetPeOEP(_In_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo);

	/// <summary>
	/// 修复重定位
	/// </summary>
	VOID PerformBaseRelocation(_Out_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo);

	/// <summary>
	///  填充新区段内容
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
	/// 获取pe文件的默认代码段
	/// </summary>
	/// <param name="FileBuffer"></param>
	/// <returns></returns>
	std::string GetPackDefaultCodeSection(CHAR* FileBuffer);


	/// <summary>
	/// 内存对齐
	/// </summary>
	/// <param name="n"></param>
	/// <param name="align"></param>
	/// <returns></returns>
	POINTER_TYPE Alignment(POINTER_TYPE n, POINTER_TYPE align)
	{
		return n % align == 0 ? n : (n / align + 1) * align;
	}

	/// <summary>
	/// 获取区块表的信息
	/// </summary>
	/// <param name="Base"></param>
	/// <param name="SectionName"></param>
	/// <returns></returns>
	PIMAGE_SECTION_HEADER GetSectionBase(POINTER_TYPE Base, LPCSTR SectionName);
	

public:
	std::string packName = ".vmp";

};

#endif // !PACK_PEOPERATION_H




