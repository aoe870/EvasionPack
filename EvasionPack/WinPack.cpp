#include "WinPack.h"
#include "Common.h"
#include <vector>
#include <time.h>
#include "lz4.h"
#include "AES.h"
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")


std::vector<std::string> DllNameTable{ "EvasionPackDll.dll" };

WinPack::WinPack(std::string path)
{
	LoadExeFile(path.c_str());

	// 2 添加新区段
	AddSection(PackTestSection.c_str(), ".text");
	AddSection(PackRelocName.c_str(), ".reloc");

	// 3 重新设置OEP
	SetOEP();

	// 修复壳重定位	
	FixReloc();

	// 7 压缩区段
	char* ptmp = (char*)DefaultCode.c_str();
//	CompressSection(ptmp);


	EncryptAllSection();// 异或加密

	// 9 填充新区段内容
	CopySectionData(PackTestSection.c_str(), PackDefaultCode.c_str());
	CopySectionData(PackRelocName.c_str(), ".reloc");
	// 10 另存为新文件
	SaveFile("../output/demo_pack1.exe");
}


DWORD WinPack::Alignment(DWORD n, DWORD align)
{
	return n % align == 0 ? n : (n / align + 1) * align;
}

PIMAGE_SECTION_HEADER WinPack::GetSection(DWORD Base, LPCSTR SectionName)
{
	// 1. 获取到区段表的第一项
	auto SectionTable = GET_SECTION_HEADER(Base);

	// 2. 获取到区段表的元素个数
	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;

	// 3. 遍历区段表，比较区段的名称，返回区段信息结构体的地址
	for (WORD i = 0; i < SectionCount; ++i)
	{
		// 如果找到就直接返回
		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
			return &SectionTable[i];
	}

	return nullptr;
}

VOID WinPack::LoadExeFile(LPCSTR FileName)
{
	// 如果文件存在，就打开文件，打开的目的只是为了读取其中的数据
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
		return;
	}

	// 获取文件的大小，并使用这个大小申请缓冲区
	FileSize = GetFileSize(FileHandle, NULL);
	if (FileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		return;
	}

	FileBase = (DWORD)calloc(FileSize, sizeof(BYTE));

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Read = 0;
	ReadFile(FileHandle, (LPVOID)FileBase, FileSize, &Read, NULL);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(FileHandle);

	//判断是否是PE文件
	IsFeFile();

	//获取代码段
	GetDefaultCodeSection();

	///////////////////////////////////////////

	// 以不执行 DllMain 的方式加载模块到当前的内存中
	DllBase = (DWORD)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	GetPackDefaultCodeSection();

	// 从 dll 中获取到 start 函数，并计算它的页内偏移(加载基址 + 区段基址 + 段内偏移)
	DWORD Start = (DWORD)GetProcAddress((HMODULE)DllBase, "start");
	StartOffset = Start - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

	// 获取到共享信息
	ShareData = (PSHAREDATA)GetProcAddress((HMODULE)DllBase, "ShareData");



}

/// <summary>
/// 添加新的区块
/// </summary>
/// <param name="SectionName">区块名称</param>
/// <param name="SrcName">壳的区块名称</param>
VOID WinPack::AddSection(LPCSTR SectionName, LPCSTR SrcName)
{

	// 1. 获取到区段表的最后一个元素的地址
	auto LastSection = &GET_SECTION_HEADER(FileBase)
		[GET_FILE_HEADER(FileBase)->NumberOfSections - 1];

	// 2. 将文件头中保存的区段数量 + 1
	GET_FILE_HEADER(FileBase)->NumberOfSections += 1;

	// 3. 通过最后一个区段，找到新添加的区段的位置
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  从 dll 中找到我们需要拷贝的区段
	auto SrcSection = GetSection(DllBase, SrcName);

	// 5. 直接将源区段的完整信息拷贝到新的区段中
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. 设置新的区段表中的数据： 名称
	memcpy(NewSection->Name, SectionName, 7);

	// 7. 设置新的区段所在的 RVA = 上一个区段的RVA + 对齐的内存大小
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(FileBase)->SectionAlignment);

	// 8. 设置新的区段所在的 FOA = 上一个区段的FOA + 对齐的文件大小
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(FileBase)->FileAlignment);

	// 9. 重新计算文件的大小，申请新的空间保存原有的数据
	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 11. 修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小
	GET_OPTIONAL_HEADER(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;
}

VOID WinPack::FixReloc()
{
	DWORD Size = 0, OldProtect = 0;

	// 获取到程序的重定位表
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);

	// 如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock)
	{
		// 如果重定位的数据在代码段，就需要修改访问属性
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, PAGE_READWRITE, &OldProtect);

		// 获取重定位项数组的首地址和重定位项的数量
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// 遍历每一个重定位项，输出内容
		for (int i = 0; i < count; ++i)
		{
			// 如果 type 的值为 3 我们才需要关注
			if (to[i].Type == 3)
			{
				// 获取到需要重定位的地址所在的位置
				DWORD* addr = (DWORD*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// 计算出不变的段内偏移 = *addr - imagebase - .text va
				DWORD item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

				// 使用这个地址，计算出新的重定位后的数据
				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
				// printf("\t%08x - %08X - %08X\n", addr, *addr, item);
			}
		}

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, OldProtect, &OldProtect);


		//-----------------------修正VirtualAddress字段--------------------------------------------

		// 重定位中VirtualAddress 字段进行修改，需要把重定位表变成可写
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, &OldProtect);

		// 修正VirtualAddress，从壳中的text到 目标程序pack段
		// 修复公式 ：VirtualAddress - 壳.text.VirtualAddress  + 目标程序.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);

	}

	// 关闭程序的重定位，目前只是修复了壳代码的重定位，并不表示源程序支持重定位
	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics = 0x8100;

	// 修改目标程序重定位表的位置到新重定位表（.stu_re）
	SetRelocTable();
}


VOID WinPack::SetRelocTable()
{
	// 获取原始程序的重定位表，进行备份
	ShareData->oldRelocRva =
		GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress;

	// 修改重定位到新的区段 （stu_re）
	GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress
		= GetSection(FileBase, PackRelocName.c_str())->VirtualAddress;

	// 修改重定位大小  目标.director[5].size = 壳.director[5].size;
	GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].Size =
		GET_NT_HEADER(DllBase)->OptionalHeader.DataDirectory[5].Size;

	// 让程序支持重定位
	GET_NT_HEADER(FileBase)->FileHeader.Characteristics &= 0xFFFFFFFE;
	GET_NT_HEADER(FileBase)->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// 备份原始加载基址，壳修复时使用
	ShareData->oldImageBase = GET_NT_HEADER(FileBase)->OptionalHeader.ImageBase;

	return VOID();
}

VOID WinPack::SetOEP()
{
	// 修改原始 oep 之前，保存 oep
	ShareData->OldOep = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;

	// --------------------AddressOfEntryPoint----------------------

	// 新的 rav = start 的段内偏移 + 新区段的 rva
	GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint = StartOffset +
		GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
}

VOID WinPack::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
{
	// 获取源区段在虚拟空间(dll->映像)中的基址
	BYTE* SrcData = (BYTE*)(GetSection(DllBase, SrcName)->VirtualAddress + DllBase);

	// 获取目标区段在虚拟空间(堆->镜像)中的基址
	BYTE* DestData = (BYTE*)(GetSection(FileBase, SectionName)->PointerToRawData + FileBase);

	// 直接进行内存拷贝
	memcpy(DestData, SrcData, GetSection(DllBase, SrcName)->SizeOfRawData);
}

VOID WinPack::SaveFile(LPCSTR FileName)
{
	// 无论文件是否存在，都要创建新的文件
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Write = 0;
	WriteFile(FileHandle, (LPVOID)FileBase, FileSize, &Write, NULL);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(FileHandle);
}

bool WinPack::CompressSection(char* SectionName)
{
	// 获取这个区段信息
	PIMAGE_SECTION_HEADER pSection = GetSection(FileBase, SectionName);
	// 压缩前位置
	char* pRoffset = (char*)(pSection->PointerToRawData + FileBase);
	// 区段在文件中的大小
	long lSize = pSection->SizeOfRawData;

	// 0 保存压缩前信息
	// 压缩数据的RVA
	ShareData->FrontCompressRva = pSection->VirtualAddress;
	// 压缩前大小Size
	ShareData->FrontCompressSize = lSize;

	// ---------------------------------开始压缩
	// 1 获取预估的压缩后的字节数:
	int compress_size = LZ4_compressBound(lSize);
	// 2. 申请内存空间, 用于保存压缩后的数据
	char* pBuff = new char[compress_size];
	// 3. 开始压缩文件数据(函数返回压缩后的大小)
	ShareData->LaterCompressSize = LZ4_compress(
		pRoffset,/*压缩前的数据*/
		pBuff, /*压缩后的数据*/
		lSize/*文件原始大小*/);

	// 4.将压缩后的数据覆盖原始数据
	memcpy(pRoffset, pBuff, ShareData->LaterCompressSize);

	// 5.修复当前区段文件大小 
	pSection->SizeOfRawData = Alignment(ShareData->LaterCompressSize, 0x200);

	// 6.将所有区段向上提升
	PIMAGE_SECTION_HEADER pFront = pSection;
	PIMAGE_SECTION_HEADER pLater = pSection + 1;
	// 没有后一个区段，就不需要提升
	while (pLater->VirtualAddress)
	{
		// 当前区段大小
		long DesSize = pFront->SizeOfRawData;
		// 移动到这个区段后面
		char* pDest = (char*)(pFront->PointerToRawData + FileBase + DesSize);

		// 下个区段大小
		long SrcSize = pLater->SizeOfRawData;
		// 下一个区段位置
		char* pSrc = (char*)(pLater->PointerToRawData + FileBase);

		// 拷贝区段
		memcpy(pDest, pSrc, SrcSize);

		// 修改下个区段位置 不加FileBase，应为不是在内存中
		pLater->PointerToRawData = pFront->PointerToRawData + DesSize;

		// 继续提升下个区段
		pFront += 1;
		pLater += 1;
	}

	// 7.重新修改文件实际大小
	// 实际大小 = 最后一个区段位置 + 最后区段大小
	FileSize = pFront->PointerToRawData + pFront->SizeOfRawData;

	// 8.重新修改文件大小
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 9.释放空间
	delete[]pBuff;

	return true;
}


/// <summary>
/// 获取默认代码段
/// </summary>
void WinPack::GetDefaultCodeSection()
{
	auto OEP = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;
	auto count = GET_NT_HEADER(FileBase)->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* SecHeader = GET_SECTION_HEADER(FileBase);
	
	for (auto iter = 0; iter < count; iter++) {
		if ((SecHeader[iter].VirtualAddress + SecHeader[iter].SizeOfRawData) > OEP && OEP > SecHeader[iter].VirtualAddress) {
			DefaultCode = std::move(std::string((char*)SecHeader[iter].Name));
			return;
		}

	}

	DefaultCode = "";
}

//加密默认代码段
void WinPack::XorSection(std::string SectionName)
{
	// 1. 获取到需要加密的区段的信息
	auto XorSection = GetSection(FileBase, ".text");

	// 2. 找到需要加密的字段所在内存中的位置
	BYTE* data = (BYTE*)(XorSection->PointerToRawData + FileBase);

	// 3. 填写解密时需要提供的信息
	srand((unsigned int)time(0));
	ShareData->key = rand() % 0xff;
	ShareData->rva = XorSection->VirtualAddress;
	ShareData->size = XorSection->SizeOfRawData;

	// 4. 循环开始进行加密
	for (int i = 0; i < ShareData->size; ++i)
	{
		data[i] ^= ShareData->key;
	}
}

/// <summary>
/// 加密所有区段
/// </summary>
void WinPack::EncryptAllSection()
{
	unsigned char key1[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//初始化aes对象
	CAES aes(key1);

	//获取区段数量
	DWORD dwSectionCount = GET_FILE_HEADER(FileBase)->NumberOfSections;
	//获取第一个区段
	IMAGE_SECTION_HEADER* pFirstSection = GET_SECTION_HEADER(FileBase);
	//用于保存数据
	ShareData->data[20][2] = { 0 };
	ShareData->index = 0;

	//DWORD dwIsTls = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".reloc");
	//DWORD dwIsTls2 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".data");
	//DWORD dwIsTls4 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".stu_re");
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rdata");
		DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".pack");


		//跳过资源 只读数据 壳区段
		if (dwIsRsrc == 0 || dwIsTls1 == 0 || dwIsTls3 == 0)// || pFirstSection[i].PointerToRawData == 0 || pFirstSection[i].SizeOfRawData == 0
		{
			continue;
		}
		else       //开始加密所有区段
		{
			//获取区段的首地址和大小
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)FileBase;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//修改属性为可写
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//加密目标区段
			aes.Cipher(pTargetSection, dwTargetSize);
			//修改回原来的属性
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//保存数据到共享信息结构体
			ShareData->data[ShareData->index][0] = pFirstSection[i].VirtualAddress;
			ShareData->data[ShareData->index][1] = dwTargetSize;
			ShareData->index++;
		}
	}
	memcpy(ShareData->key1, key1, 16);
}

void WinPack::GetPackDefaultCodeSection()
{
	auto OEP = GET_OPTIONAL_HEADER(DllBase)->AddressOfEntryPoint;
	auto count = GET_NT_HEADER(DllBase)->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* SecHeader = GET_SECTION_HEADER(DllBase);

	for (auto iter = 0; iter < count; iter++) {
		if ((SecHeader[iter].VirtualAddress + SecHeader[iter].SizeOfRawData) > OEP && OEP > SecHeader[iter].VirtualAddress) {
			PackDefaultCode = std::move(std::string((char*)SecHeader[iter].Name));
			return;
		}

	}
}

/// <summary>
/// 判断是否是PE文件
/// </summary>
/// <returns></returns>
bool WinPack::IsFeFile()
{

	if (GET_DOS_HEADER(FileBase)->e_magic != IMAGE_DOS_SIGNATURE) {
		
		PrintLog(EVASION_ERROR_FILETYPE_ERROR);
		return false;
	}

	if (GET_NT_HEADER(FileBase)->FileHeader.NumberOfSections == 1) {

		PrintLog(EVASION_ERROR_FILE_ISCOMPRESSED);
		return false;
	}

	if ((GET_SECTION_HEADER(FileBase) + 1)->VirtualAddress < (GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint)) {

		PrintLog(EVASION_ERROR_FILE_ISCOMPRESSED);
		return false;
	}

	return true;
}
