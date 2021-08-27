#pragma once
#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include <iostream>
#include <Windows.h>
#include "../EvasionPackDll/stub.h"
#include "PeOperation.h"


class WinPack
{

public:

	WinPack(TCHAR* path);

	//开始保护
	void StartProtect(HWND hwndDlg, TCHAR* strPath, BYTE byXor, PROTECTOR	pProctect);

	//机器码绑定(将CPU序列号同主程序入口进行亦或)
	void XorMachineCode(ULONGLONG cpuId, PEInfo& peinfo);

	//获取CPU序列号(64位或者32位通用)
	ULONGLONG GetCPUID();

	//加密代码段
	DWORD XorCode(BYTE byXOR, PEInfo peinfo);

	//获取IAT表信息和重定位信息
	void getinfo(char* cbuff);

	//保存IAT表
	void SaveImportTab(char* m_pFileBuf);

	//抹去导入表所有信息
	void ClearImportTab(char* m_pFileBuf);

	//清除不需要的目录信息
	void ClearDirTable(char* filebuff);

	//合并目标PE和Stub.dll
	PBYTE MergeSection(PEInfo peinfo, PEInfo stubpeinfo, PBYTE lpMod, BYTE byXor);

	//保存文件
	void SaveFile_pack(TCHAR* strPath, char* NewBuffer, ULONG_PTR m_uTotalSize);

private:
	AllocMemory m_allocMemory;

	PMYIMPORT		m_pMyImport;
	PVOID			m_pModNameBuf;
	PVOID			m_pFunNameBuf;
	ULONG_PTR		m_dwNumOfIATFuns = 0;
	ULONG_PTR		m_dwSizeOfModBuf = 0;
	ULONG_PTR		m_dwSizeOfFunBuf = 0;


	ULONG_PTR					m_IATSectionBase = 0;	//IAT所在段基址
	DWORD						m_IATSectionSize = 0;	//IAT所在段大小

	IMAGE_DATA_DIRECTORY		m_PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY		m_PEImportDir;		//导入表信息


	ULONG_PTR m_uTotalSize = 0;//记录合并后的总大小
};
#endif // PACK_WINPACK_H