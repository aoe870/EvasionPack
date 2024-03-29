#pragma once
#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include <iostream>
#include <Windows.h>

#define GET_DOS_HEADER(x) ((PIMAGE_DOS_HEADER)(x))
#define GET_NT_HEADER(x) ((PIMAGE_NT_HEADERS)((DWORD)GET_DOS_HEADER(x)->e_lfanew + (DWORD)(x)))
#define GET_FILE_HEADER(x) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(x)->FileHeader))
#define GET_OPTIONAL_HEADER(x) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(x)->OptionalHeader))
#define GET_SECTION_HEADER( x ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(GET_NT_HEADER(x)) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((GET_NT_HEADER(x)))->FileHeader.SizeOfOptionalHeader   \
    ))

// 重定位项结构体
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

// 共享数据结构体
typedef struct _SHAREDATA
{
	long OldOep = 0;// 原始 oep
	long rva = 0;// 加密的rva
	long size = 0;// 加密的大小
	BYTE key = 0;// 加密的 key
	long oldRelocRva = 0;// 原始重定位表位置
	long oldImageBase = 0;// 原始加载基址

	DWORD FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//AES解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	

	int index2 = 0;			  //加密的区段数量 用的时候需要-1
	int data2[20][2];  //加密的区段RVA和Size	


	DWORD dwDataDir[20][3];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数

	long ImportRva;

	DWORD TlsCallbackFuncRva;
	bool bIsTlsUseful;

} SHAREDATA, * PSHAREDATA;


class WinPack
{

public:

	WinPack(std::string path, std::string fileName);
	DWORD Alignment(DWORD n, DWORD align);// 文件/内存对齐
	PIMAGE_SECTION_HEADER GetSection(DWORD Base, LPCSTR SectionName);// 获取区段头信息

public:
	void LoadExeFile(LPCSTR FileName);// 读取目标程序
	void AddSection(LPCSTR SectionName, LPCSTR SrcName);//添加新区段
	void FixReloc();// 修复壳重定位
	void SetRelocTable();// 修改目标程序数据目标表，重定位表的位置到新重定位表（.stu_re）
	void SetOEP();// 重新设置OEP
	void CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// 设置新区段内容(后者拷贝至前者
	void SaveFile(LPCSTR FileName);// 另存新文件
	bool CompressSection(std::string SectionName);// 压缩区段
	void GetDefaultCodeSection(); //获取默认代码段
	void XorSection(std::string SectionName);// 异或加密区段
	void EncryptAllSection(); //全段加密
	void GetPackDefaultCodeSection();//获取壳的默认代码段
	bool IsFeFile();
	void SetClearImport();

private:
	DWORD FileSize = 0;// 文件大小,申请内存/保存文件时会用到
	DWORD FileBase = 0;// 文件基地址; DWORD是为了计算方便
	DWORD DllBase = 0;// dll 的加载基址/模块句柄
	DWORD StartOffset = 0;// start 函数的段内偏移,用于计算新OEP
	PSHAREDATA ShareData = nullptr;// 定义共享数据,向壳代码dll提供信息(对共享数据的操作都要写在拷贝区段之前)
	std::string PackDefaultCode = "";
	std::string DefaultCode = "";			//待加壳程序默认代码段
	std::string PackRelocName = ".stu_re";	//壳的重定位代码段名称(加壳后)
	std::string PackTestSection = ".pack";	//壳的默认代码段名称(加壳后)

};
#endif // PACK_WINPACK_H