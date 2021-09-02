//#include "WinPack64.h"
//#include "Common.h"
//#include <vector>
//#include <time.h>
//#include "lz4.h"
//#include "AES.h"
//#include <DbgHelp.h>
//#include "PeOperation.h"
//
//#pragma comment(lib, "DbgHelp.lib")
//
//std::vector<std::string> DllNameTable{ "EvasionPackDll.dll" };
//
//WinPack64::WinPack64() {
//
//#ifdef _WIN64
//	//std::string path = "../output/demoX64.exe";
//	//std::string name = "../output/demoX64_pack.exe";
//
//	std::string path = "../output/shell64.exe";
//	std::string name = "../output/shell64_pack.exe";
//#else
//	std::string path = "../output/demo.exe";
//	std::string name = "../output/demo_pack.exe";
//
//	//std::string path = "../output/shell32.exe";
//	//std::string name = "../output/shell32_pack.exe";
//#endif
//
//	LoadExeFile(path.c_str());
//
//	// 2 添加新区段
//	AddSection(PackTestSection.c_str(), ".text");
//
//	// 3 重新设置OEP
//	SetOEP();
//
//	// 修复壳重定位	
//	FixReloc();
//
//	////压缩区段
////	CompressSection(DefaultCode);
//
//	// //异或加密
//	//EncryptAllSection();
//
//	XorSection(".text");
//
//	// 9 填充新区段内容
//	CopySectionData(PackTestSection.c_str(), PackDefaultCode.c_str());
//
//	// 10 另存为新文件
//	SaveFile(name.c_str());
//
//	return;
//}
//
///// <summary>
///// 内存对齐
///// </summary>
///// <param name="n"></param>
///// <param name="align"></param>
///// <returns></returns>
//POINTER_TYPE WinPack64::Alignment(POINTER_TYPE n, POINTER_TYPE align)
//{
//	return n % align == 0 ? n : (n / align + 1) * align;
//}
//
///// <summary>
///// 获取模块表段
///// </summary>
///// <param name="Base">模块基址</param>
///// <param name="SectionName">表块名
///// </param>
///// <returns></returns>
//PIMAGE_SECTION_HEADER WinPack64::GetSection(POINTER_TYPE Base, LPCSTR SectionName)
//{
//	// 1. 获取到区段表的第一项
//	auto SectionTable = GET_SECTION_HEADER(Base);
//
//	// 2. 获取到区段表的元素个数
//	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;
//
//	// 3. 遍历区段表，比较区段的名称，返回区段信息结构体的地址
//	for (WORD i = 0; i < SectionCount; ++i)
//	{
//		// 如果找到就直接返回
//		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
//			return &SectionTable[i];
//	}
//
//	return nullptr;
//}
//
///// <summary>
///// 
///// </summary>
///// <param name="FileName"></param>
//VOID WinPack64::LoadExeFile(LPCSTR FileName)
//{
//	// 如果文件存在，就打开文件，打开的目的只是为了读取其中的数据
//	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, NULL,
//		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	if (FileHandle == INVALID_HANDLE_VALUE) {
//		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
//		return;
//	}
//
//	// 获取文件的大小，并使用这个大小申请缓冲区
//	FileSize = GetFileSize(FileHandle, NULL);
//	if (FileSize == 0xFFFFFFFF) {
//		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
//		return;
//	}
//
//	FileBase = (POINTER_TYPE)calloc(FileSize, sizeof(BYTE));
//
//	// 将目标文件的内容读取到创建的缓冲区中
//	DWORD Read = 0;
//	ReadFile(FileHandle, (LPVOID)FileBase, FileSize, &Read, NULL);
//
//	// 为了防止句柄泄露应该关闭句柄
//	CloseHandle(FileHandle);
//
//	//判断是否是PE文件
//	IsFeFile();
//
//	//获取代码段
//	GetDefaultCodeSection();
//
//	///////////////////////////////////////////
//	
//	// 以不执行 DllMain 的方式加载模块到当前的内存中
//	DllBase = (POINTER_TYPE)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
//
//	GetPackDefaultCodeSection();
//
//	// 从 dll 中获取到 start 函数，并计算它的页内偏移(加载基址 + 区段基址 + 段内偏移)
//	POINTER_TYPE Start = (POINTER_TYPE)GetProcAddress((HMODULE)DllBase, "start");
//	StartOffset = Start - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//
//	// 获取到共享信息
//	ShareData = (PSHAREDATAA)GetProcAddress((HMODULE)DllBase, "ShareData");
//
//}
//
///// <summary>
///// 添加新的区块
///// </summary>
///// <param name="SectionName">区块名称</param>
///// <param name="SrcName">壳的区块名称</param>
//VOID WinPack64::AddSection(LPCSTR SectionName, LPCSTR SrcName)
//{
//
//	// 1. 获取到区段表的最后一个元素的地址
//	auto LastSection = &GET_SECTION_HEADER(FileBase)
//		[GET_FILE_HEADER(FileBase)->NumberOfSections - 1];
//
//	// 2. 将文件头中保存的区段数量 + 1
//	GET_FILE_HEADER(FileBase)->NumberOfSections += 1;
//
//	// 3. 通过最后一个区段，找到新添加的区段的位置
//	auto NewSection = LastSection + 1;
//	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
//
//	// 4.  从 dll 中找到我们需要拷贝的区段
//	auto SrcSection = GetSection(DllBase, SrcName);
//
//	// 5. 直接将源区段的完整信息拷贝到新的区段中
//	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));
//
//	// 6. 设置新的区段表中的数据： 名称
//	memcpy(NewSection->Name, SectionName, 7);
//
//	// 7. 设置新的区段所在的 RVA = 上一个区段的RVA + 对齐的内存大小
//	NewSection->VirtualAddress = LastSection->VirtualAddress +
//		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(FileBase)->SectionAlignment);
//
//	// 8. 设置新的区段所在的 FOA = 上一个区段的FOA + 对齐的文件大小
//	NewSection->PointerToRawData = LastSection->PointerToRawData +
//		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(FileBase)->FileAlignment);
//
//	// 9. 重新计算文件的大小，申请新的空间保存原有的数据
//	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
//	FileBase = (POINTER_TYPE)realloc((VOID*)FileBase, FileSize);
//
//	// 11. 修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小
//	GET_OPTIONAL_HEADER(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;
//}
//
///// <summary>
///// 
///// </summary>
//VOID WinPack64::FixReloc()
//{
//
//	DWORD Size = 0, OldProtect = 0;
//
//	// 获取到程序的重定位表
//	PIMAGE_DATA_DIRECTORY pDataDirectory = GET_OPTIONAL_HEADER(DllBase)->DataDirectory;
//	auto RealocTable = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)DllBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
//
//
//	// 如果 SizeOfBlock 不为空，就说明存在重定位块
//	while (RealocTable->SizeOfBlock)
//	{
//	
//		// 如果重定位的数据在代码段，就需要修改访问属性
//		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
//			0x1000, PAGE_READWRITE, &OldProtect);
//		
//		// 获取重定位项数组的首地址和重定位项的数量
//		int count = (RealocTable->SizeOfBlock - 8) / 2;
//		TypeOffsets* to = (TypeOffsets*)(RealocTable + 1);
//		
//		// 遍历每一个重定位项，输出内容
//		for (int i = 0; i < count; i++)
//		{
//			// 如果 type 的值为 3 我们才需要关注
//			if (to[i].Type == 3)
//			{
//							
//				// 获取到需要重定位的地址所在的位置
//				POINTER_TYPE* addr = (POINTER_TYPE*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);
//
//				// 计算出不变的段内偏移 = *addr - imagebase - .text va
//				POINTER_TYPE item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//
//
//				// 使用这个地址，计算出新的重定位后的数据
//				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//				
//				
//			}
//		}
//		
//		// 还原原区段的的保护属性
//		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
//			0x1000, OldProtect, &OldProtect);
//
//
//		//-----------------------修正VirtualAddress字段--------------------------------------------
//
//		// 重定位中VirtualAddress 字段进行修改，需要把重定位表变成可写
//		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
//			0x4, PAGE_READWRITE, &OldProtect);
//
//		// 修正VirtualAddress，从壳中的text到 目标程序pack段
//		// 修复公式 ：VirtualAddress - 壳.text.VirtualAddress  + 目标程序.pack.VirtualAddress
//		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//		RealocTable->VirtualAddress += GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//
//		// 还原原区段的的保护属性
//		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
//			0x1000, OldProtect, &OldProtect);
//
//		// 找到下一个重定位块
//		RealocTable = (PIMAGE_BASE_RELOCATION)
//			((POINTER_TYPE)RealocTable + RealocTable->SizeOfBlock);
//
//	}
//
//	// 关闭程序的重定位，目前只是修复了壳代码的重定位，并不表示源程序支持重定位
//	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics = 0;
//
//}
//
///// <summary>
///// 重新设置OEP
///// </summary>
//VOID WinPack64::SetOEP()
//{
//	// 修改原始 oep 之前，保存 oep
//	ShareData->OldOep = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;
//
//	// --------------------AddressOfEntryPoint----------------------
//
//	// 新的 rav = start 的段内偏移 + 新区段的 rva
//	GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint = StartOffset +
//		GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//}
//
///// <summary>
///// 填充新区段内容
///// </summary>
///// <param name="SectionName"></param>
///// <param name="SrcName"></param>
//VOID WinPack64::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
//{
//	// 获取源区段在虚拟空间(dll->映像)中的基址
//	BYTE* SrcData = (BYTE*)(GetSection(DllBase, SrcName)->VirtualAddress + DllBase);
//
//	// 获取目标区段在虚拟空间(堆->镜像)中的基址
//	BYTE* DestData = (BYTE*)(GetSection(FileBase, SectionName)->PointerToRawData + FileBase);
//
//	// 直接进行内存拷贝
//	memcpy(DestData, SrcData, GetSection(DllBase, SrcName)->SizeOfRawData);
//}
//
///// <summary>
///// 
///// </summary>
///// <param name="FileName"></param>
//VOID WinPack64::SaveFile(LPCSTR FileName)
//{
//	// 无论文件是否存在，都要创建新的文件
//	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, NULL,
//		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	// 将目标文件的内容读取到创建的缓冲区中
//	DWORD Write = 0;
//	WriteFile(FileHandle, (LPVOID)FileBase, FileSize, &Write, NULL);
//
//	// 为了防止句柄泄露应该关闭句柄
//	CloseHandle(FileHandle);
//}
//
///// <summary>
///// 获取默认代码段
///// </summary>
//void WinPack64::GetDefaultCodeSection()
//{
//	auto OEP = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;
//	auto count = GET_NT_HEADER(FileBase)->FileHeader.NumberOfSections;
//	IMAGE_SECTION_HEADER* SecHeader = GET_SECTION_HEADER(FileBase);
//
//	for (auto iter = 0; iter < count; iter++) {
//		if ((SecHeader[iter].VirtualAddress + SecHeader[iter].SizeOfRawData) > OEP && OEP > SecHeader[iter].VirtualAddress) {
//			DefaultCode = std::move(std::string((char*)SecHeader[iter].Name));
//			return;
//		}
//	}
//
//	DefaultCode = "";
//}
//
///// <summary>
///// 加密默认代码段
///// </summary>
///// <param name="SectionName"></param>
//void WinPack64::XorSection(std::string SectionName)
//{
//
//	//获取第一个区段
//	IMAGE_SECTION_HEADER* pFirstSection = GET_SECTION_HEADER(FileBase);
//	ShareData->index = 0;
//	for (int iter = 0; iter < GET_FILE_HEADER(FileBase)->NumberOfSections; iter++) {
//
//		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".rsrc");
//		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".rdata");
//		DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".pack"); 
//		DWORD dwIscblt = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".cblt");
//		if (dwIsRsrc == 0 || dwIsTls1 == 0 || dwIsTls3 == 0 || dwIscblt == 0) {
//			continue;
//		}
//		else
//		{
//			
//			std::string sTemp(reinterpret_cast<const char*>(pFirstSection[iter].Name));
//			// 1. 获取到需要加密的区段的信息
//			auto XorSection = GetSection(FileBase, sTemp.c_str());
//
//			if (XorSection->SizeOfRawData == 0) {
//				continue;
//			}
//
//			// 2. 找到需要加密的字段所在内存中的位置
//			BYTE* data = (BYTE*)(XorSection->PointerToRawData + FileBase);
//
//			// 3. 填写解密时需要提供的信息
//			srand((unsigned int)time(0));
//			ShareData->key[iter] = rand() % 0xff;
//			ShareData->rva[iter] = XorSection->VirtualAddress;
//			ShareData->size[iter] = XorSection->SizeOfRawData;
//
//			// 4. 循环开始进行加密
//			for (int i = 0; i < ShareData->size[iter]; ++i)
//			{
//				data[i] ^= ShareData->key[iter];
//			}
//
//			ShareData->index += 1;
//		}
//	
//	}
//	
//}
//
//void WinPack64::GetPackDefaultCodeSection()
//{
//	auto OEP = GET_OPTIONAL_HEADER(DllBase)->AddressOfEntryPoint;
//	auto count = GET_NT_HEADER(DllBase)->FileHeader.NumberOfSections;
//	IMAGE_SECTION_HEADER* SecHeader = GET_SECTION_HEADER(DllBase);
//
//	for (auto iter = 0; iter < count; iter++) {
//		if ((SecHeader[iter].VirtualAddress + SecHeader[iter].SizeOfRawData) > OEP && OEP > SecHeader[iter].VirtualAddress) {
//			PackDefaultCode = std::move(std::string((char*)SecHeader[iter].Name));
//			return;
//		}
//
//	}
//}
//
///// <summary>
///// 判断是否是PE文件
///// </summary>
///// <returns></returns>
//bool WinPack64::IsFeFile()
//{
//
//	if (GET_DOS_HEADER(FileBase)->e_magic != IMAGE_DOS_SIGNATURE) {
//
//		PrintLog(EVASION_ERROR_FILETYPE_ERROR);
//		return false;
//	}
//
//	if (GET_NT_HEADER(FileBase)->FileHeader.NumberOfSections == 1) {
//
//		PrintLog(EVASION_ERROR_FILE_ISCOMPRESSED);
//		return false;
//	}
//
//	return true;
//}