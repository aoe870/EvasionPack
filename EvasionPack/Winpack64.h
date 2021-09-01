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

// 重定位项结构体
struct TypeOffsets
{
	WORD Offset : 12;
	WORD Type : 4;
};

// 共享数据结构体
typedef struct _SHAREDATAA
{
	POINTER_TYPE OldOep = 0;// 原始 oep
	POINTER_TYPE rva[10] = {};// 加密的rva
	long size[10] = {};// 加密的大小
	BYTE key[10] = {};// 加密的 key

	long oldRelocRva = 0;// 原始重定位表位置
	long oldImageBase = 0;// 原始加载基址

	POINTER_TYPE FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//AES解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	

} SHAREDATAA, * PSHAREDATAA;

class WinPack64
{

public:
	WinPack64();
	POINTER_TYPE Alignment(POINTER_TYPE n, POINTER_TYPE align);// 文件/内存对齐
	PIMAGE_SECTION_HEADER GetSection(POINTER_TYPE Base, LPCSTR SectionName);// 获取区段头信息

public:
	void LoadExeFile(LPCSTR FileName);// 读取目标程序
	void AddSection(LPCSTR SectionName, LPCSTR SrcName);//添加新区段
	void FixReloc();// 修复壳重定位
	void SetOEP();// 重新设置OEP
	void CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// 设置新区段内容(后者拷贝至前者
	void SaveFile(LPCSTR FileName);// 另存新文件
	void GetDefaultCodeSection(); //获取默认代码段
	void XorSection(std::string SectionName);// 异或加密区段
	void GetPackDefaultCodeSection();//获取壳的默认代码段
	bool IsFeFile();

private:
	POINTER_TYPE FileSize = 0;// 文件大小,申请内存/保存文件时会用到
	POINTER_TYPE FileBase = 0;// 文件基地址; DWORD是为了计算方便
	POINTER_TYPE DllBase = 0;// dll 的加载基址/模块句柄
	POINTER_TYPE StartOffset = 0;// start 函数的段内偏移,用于计算新OEP
	PSHAREDATAA ShareData = nullptr;// 定义共享数据,向壳代码dll提供信息(对共享数据的操作都要写在拷贝区段之前)
	std::string PackDefaultCode = "";
	std::string DefaultCode = "";			//待加壳程序默认代码段
	std::string PackRelocName = ".stu_re";	//壳的重定位代码段名称(加壳后)
	std::string PackTestSection = ".pack";	//壳的默认代码段名称(加壳后)



};
#endif // PACK_WINPACK_H