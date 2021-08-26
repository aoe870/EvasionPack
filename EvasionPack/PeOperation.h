#pragma once
#ifndef PACKPEOPERATION_H
#define PACKPEOPERATION_H

#include <iostream>
#include <Windows.h>
#include "Common.h"
#include "ShareData.h"
#include "AllocMemory.h"

//PE结构的信息结构体
typedef struct PEInformation
{
	POINTER_TYPE FileBase;			//文件在内存里的地址
	POINTER_TYPE FileSize;				//文件大小
	POINTER_TYPE NumberOfSections;		//区段数目
	POINTER_TYPE SectionAlignment;		//内存对齐
	POINTER_TYPE FileAlignment;			//文件对齐
	POINTER_TYPE SizeofImage;			//镜像大小
	POINTER_TYPE SizeOfHeaders;			//头大小
	POINTER_TYPE BaseOfData;			//数据基址
	POINTER_TYPE ImageBase;				//镜像基址
	POINTER_TYPE SizeOfCode;			//代码节大小
	POINTER_TYPE AddressOfEntryPoint;	//OEP(RVA)入口点
	POINTER_TYPE BaseOfCode;			//代码基址
	POINTER_TYPE SizeOfOptionHeaders;	//可选头大小
	POINTER_TYPE e_lfanes;				//PE文件头地址
	IMAGE_DATA_DIRECTORY* DataDirectory;	//目录
	PIMAGE_NT_HEADERS pNtHeader;			//Nt头
	PIMAGE_SECTION_HEADER pSectionHeader;	//节头
	PIMAGE_OPTIONAL_HEADER OptionalHeader;	//可选PE头
}PEInfo, * pPEInfo;

class PeOperation :public AllocMemory
{
public:
	AllocMemory m_alloc;

public:

	/// <summary>
	/// 内存对齐
	/// </summary>
	/// <param name="uSize"> 输入的值 </param>
	/// <param name="ualign"> 内存对齐值 </param>
	/// <returns></returns>
	ULONG_PTR Alignment(_In_ ULONG_PTR uValue, ULONG_PTR uAlign);

	/// <summary>
	/// 判断是否是PE文件
	/// </summary>
	/// <param name="pFileBuffer"></param>
	/// <param name="hwndDlg"></param>
	/// <returns></returns>
	BOOL IsPEFile(UCHAR* pFileBuffer, HWND hwndDlg = 0);

	/// <summary>
	/// 修复基址重定位
	/// </summary>
	/// <param name="buff"></param>
	/// <param name="Value"></param>
	VOID PerformBaseRelocation(POINTER_TYPE buff, POINTER_TYPE Value);


	/// <summary>
	/// 修复IAT表
	/// </summary>
	/// <param name="buff"></param>
	/// <returns></returns>
	BOOL RebuildImportTable(POINTER_TYPE buff);

	/// <summary>
	/// 加载PE文件格式
	/// </summary>
	/// <param name="FileName"></param>
	/// <returns></returns>
	BOOL LoadPeFile(LPCSTR FileName, _Out_ PEInformation* pPEInfor);

	/// <summary>
	/// 添加新节
	/// </summary>
	/// <param name="pFileBuff">模块地址</param>
	/// <param name="AddSize"></param>
	/// <param name="secname"></param>
	/// <returns></returns>
	BOOL addSeciton(POINTER_TYPE pFileBuff, DWORD AddSize, char secname[8] = { 0 });


	/// <summary>
	/// 获取目录表的地址
	/// </summary>
	/// <param name="module"></param>
	/// <param name="idx"></param>
	/// <returns></returns>
	DWORD GET_HEADER_DICTIONARY(POINTER_TYPE module, int idx);

	/// <summary>
	/// 文件在内存中展开
	/// </summary>
	/// <param name="pFileBuff"></param>
	/// <param name="FileSize"></param>
	/// <returns></returns>
	POINTER_TYPE StretchFile(POINTER_TYPE pFileBuff, DWORD FileSize);

	/// <summary>
	/// 把PE文件还原成文件磁盘大小
	/// </summary>
	/// <param name="imgbuffer"></param>
	/// <param name="length"></param>
	/// <returns></returns>
	CHAR* ImageBuff_To_FileBuff(char* imgbuffer, DWORD length);

	/// <summary>
	/// 更新PE结构信息
	/// </summary>
	/// <param name="pFilebuff"></param>
	/// <param name="pPEInfor"></param>
	/// <param name="dwFileSize"></param>
	/// <returns></returns>
	BOOL GetPEInformation_1(char* pFilebuff, PEInformation* pPEInfor, DWORD dwFileSize = 0);
};

#endif // PACKPEOPERATION_H

