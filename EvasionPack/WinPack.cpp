#include "WinPack.h"
#include <Windows.h>

std::vector<std::string> DllNameTable{ "EvasionPackDll.dll" };

WinPack::WinPack(std::string path, std::string newFileName)
{

	//DWORD Frame = 1110; /* MUST be the very first thing in the function */
	//DWORD abc = 12;

	//PDWORD pFrame;

	//Frame++; /* make sure that Frame doesn't get optimized out */

	//pFrame = (PDWORD)(&Frame);
	///*... do stuff with pFrame here*/
	//
	//auto add = (PDWORD)pFrame + 8;

	PEInfo peinfo;
	PeOperation pe;
	pe.LoadPeFIle(path, &peinfo);
	
	if (FALSE == pe.IsPEFile((UCHAR*)peinfo.FileBuffer)) {
		return;
	}
	
	pe.GetPeInfo(&peinfo);

	/*----------------------------------------------------------------------------------*/
	/* 加载dll																			*/
	/*----------------------------------------------------------------------------------*/

	PEInfo dllinfo;
	dllinfo.FileBuffer = (POINTER_TYPE)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	
	
	if (dllinfo.FileBuffer == 0xFFFFFFFF || dllinfo.FileBuffer == 0xFFFFFFFFFFFFFFFF) {
		return;
	}

	pe.GetPeInfo(&dllinfo);

	// 获取到共享信息
	auto shareAdd = (PSHAREDATA)GetProcAddress((HMODULE)dllinfo.FileBuffer, "ShareData");

	if (shareAdd == NULL) {
		return;
	}
	PSHAREDATA ShareData;
	ShareData = shareAdd;

	//保存PE信息 信息用于壳还原数据时用到
	SavaPeInfo(&peinfo, ShareData);

	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	//
	//添加新的区块
	pe.AddSection(&peinfo, &dllinfo);

	//重设入口
	pe.SetPeOEP(&peinfo, &dllinfo);

	//修复重定位
	pe.PerformBaseRelocation(&peinfo, &dllinfo);

	//疑惑加密
//	pe.XorAllSection(&peinfo, ShareData);

	//aes在加密一次
	ShareData->sEncryption = pe.EncryptAllSection(&peinfo);

	//压缩
//	pe.CompressSection(&peinfo, ShareData);

	//复制区段
	pe.CopySectionData(&peinfo, &dllinfo);

	//保存文件
	SaveFile(&peinfo, newFileName);
}

VOID WinPack::SavaPeInfo(pPEInfo peinfo, PSHAREDATA data)
{
	data->oldOep = peinfo->AddressOfEntryPoint;
	data->oldRelocRva = peinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	data->oldImageBase = peinfo->ImageBase;
	data->oldImportRva = peinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

}

VOID WinPack::SaveFile(pPEInfo pPEInfor, std::string name)
{
	if (name != "") {
		FileName = name;
	}
	// 无论文件是否存在，都要创建新的文件
	HANDLE FileHandle = CreateFileA(FileName.c_str(), GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Write = 0;
	auto tmp = WriteFile(FileHandle, (LPVOID)pPEInfor->FileBuffer, pPEInfor->FileSize, &Write, NULL);	

	PrintLog("succeed !", LOGTYPE_OUTPUT);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(FileHandle);
}