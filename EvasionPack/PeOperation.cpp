#include "PeOperation.h"

#define GET_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)(base))
#define GET_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((ULONG_PTR)GET_DOS_HEADER(base)->e_lfanew + (ULONG_PTR)(base)))
#define GET_FILE_HEADER(base) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(base)->FileHeader))
#define GET_OPTIONAL_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(base)->OptionalHeader))
#define GET_SECTION_HEADER( base ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(GET_NT_HEADER(base)) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((GET_NT_HEADER(base)))->FileHeader.SizeOfOptionalHeader   \
    ))

BOOLEAN PeOperation::LoadPeFIle(_In_ std::string path, _Out_ pPEInfo pPEInfor)
{

	HANDLE hFileHandle = CreateFile(StringToLPCWSTR(path), GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileHandle == INVALID_HANDLE_VALUE) {
		CloseHandle(hFileHandle);
		return FALSE;
	}

	// 获取文件的大小，并使用这个大小申请缓冲区
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		CloseHandle(hFileHandle);
		return FALSE;
	}
	//POINTER_TYPE pFileBuf = (POINTER_TYPE)malloc(pFileSize + 100);
	POINTER_TYPE pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));
	//POINTER_TYPE pFileBuf = (POINTER_TYPE)m_alloc.auto_malloc<CHAR*>(pFileSize);

	DWORD Read = 0;
	ReadFile(hFileHandle, (LPVOID)pFileBuf, pFileSize, &Read, NULL);
	 
	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(hFileHandle);
	 
	//2.1 判断是否为PE文件
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBoxA(NULL, "不是MZ开头", "提示", MB_OK);
		return 0;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((POINTER_TYPE)pFileBuf + pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((POINTER_TYPE)OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, "不是PE文件", "提示", MB_OK);
		return 0;
	}
	
	//把PE信息存入PEInformation结构体里
	pPEInfor->FileBuffer = (POINTER_TYPE)pFileBuf;
	pPEInfor->FileSize = pFileSize;
	return TRUE;
}


BOOLEAN PeOperation::IsPEFile(UCHAR* pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
	//	MessageBoxA(hwndDlg, "不是有效的MZ标志!", "提示", NULL);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
	//	MessageBoxA(hwndDlg, "不是有效的PE标志!", "提示", NULL);
		return FALSE;
	}
#ifdef _WIN64
	if (pNTHeader->OptionalHeader.Magic != 0x20B)
	{
	//	MessageBoxA(hwndDlg, "不是有效的64位PE程序!", "提示", NULL);
		return FALSE;
	}
#else
	if (pNTHeader->OptionalHeader.Magic != 0x10B)
	{
		//MessageBoxA(hwndDlg, "不是有效的32位PE程序!", "提示", NULL);
		return FALSE;
	}
#endif // _WIN64



	return TRUE;
}


VOID PeOperation::GetPeInfo(pPEInfo pPEInfor)
{
	auto pFilebuff = pPEInfor->FileBuffer;

	//2.2 把PE信息存入PEInformation结构体里
	pPEInfor->AddressOfEntryPoint = GET_OPTIONAL_HEADER(pFilebuff)->AddressOfEntryPoint;
	pPEInfor->BaseOfCode = GET_OPTIONAL_HEADER(pFilebuff)->BaseOfCode;
	pPEInfor->pNtHeader = GET_NT_HEADER(pFilebuff);
	pPEInfor->OptionalHeader = GET_OPTIONAL_HEADER(pFilebuff);
	pPEInfor->pSectionHeader = GET_SECTION_HEADER(pFilebuff);
	pPEInfor->DataDirectory = GET_OPTIONAL_HEADER(pFilebuff)->DataDirectory;
	pPEInfor->e_lfanes = GET_DOS_HEADER(pFilebuff)->e_lfanew;
	pPEInfor->FileAlignment = GET_OPTIONAL_HEADER(pFilebuff)->FileAlignment;
	pPEInfor->ImageBase = GET_OPTIONAL_HEADER(pFilebuff)->ImageBase;
	pPEInfor->NumberOfSections = GET_FILE_HEADER(pFilebuff)->NumberOfSections;
	pPEInfor->SectionAlignment = GET_OPTIONAL_HEADER(pFilebuff)->SectionAlignment;
	pPEInfor->SizeOfCode = GET_OPTIONAL_HEADER(pFilebuff)->SizeOfCode;
	pPEInfor->SizeOfHeaders = GET_OPTIONAL_HEADER(pFilebuff)->SizeOfHeaders;
	pPEInfor->SizeofImage = GET_OPTIONAL_HEADER(pFilebuff)->SizeOfImage;
	pPEInfor->SizeOfOptionHeaders = GET_FILE_HEADER(pFilebuff)->SizeOfOptionalHeader;
	pPEInfor->DataDirectory = GET_OPTIONAL_HEADER(pFilebuff)->DataDirectory;	//目录
	pPEInfor->pNtHeader = GET_NT_HEADER(pFilebuff);			//Nt头
	pPEInfor->pSectionHeader = GET_SECTION_HEADER(pFilebuff);	//节头
	pPEInfor->OptionalHeader = GET_OPTIONAL_HEADER(pFilebuff);	//可选PE头
#ifdef _WIN64

#else
	pPEInfor->BaseOfData = GET_OPTIONAL_HEADER(pFilebuff)->BaseOfData;
#endif

	//判断文件几位
	if (GET_OPTIONAL_HEADER(pFilebuff)->Magic == 0x10B)
	{
		pPEInfor->Operand = PE_OPERAND_32;

	}
	else if (GET_OPTIONAL_HEADER(pFilebuff)->Magic == 0x20B) {

		pPEInfor->Operand = PE_OPERAND_64;
	}

	pPEInfor->DefaultCode = std::move(GetPackDefaultCodeSection((CHAR*)pPEInfor->FileBuffer));
}

VOID PeOperation::AddSection(_In_ pPEInfo pPEInfor, _In_ pPEInfo Dllpe, std::string Name)
{

	packName = Name;

	// 获取到区段表的最后一个元素的地址
	auto LastSection = &GET_SECTION_HEADER(pPEInfor->FileBuffer)
		[GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections - 1];

	// 将文件头中保存的区段数量 + 1
	GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections += 1;

	// 通过最后一个区段，找到新添加的区段的位置
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 从 dll 中找到我们需要拷贝的区段
	auto SrcSection = GetSectionBase(Dllpe->FileBuffer, Dllpe->DefaultCode.c_str());

	// 直接将源区段的完整信息拷贝到新的区段中
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 设置新的区段表中的数据： 名称
	memcpy(NewSection->Name, Name.c_str(), 7);

	// 设置新的区段所在的 RVA = 上一个区段的RVA + 对齐的内存大小
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->SectionAlignment);

	// 设置新的区段所在的 FOA = 上一个区段的FOA + 对齐的文件大小
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->FileAlignment);

		// 重新计算文件的大小，申请新的空间保存原有的数据
	auto FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	auto FileBase = (POINTER_TYPE)realloc((VOID*)pPEInfor->FileBuffer, FileSize);

	// 修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小
	GET_OPTIONAL_HEADER(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	pPEInfor->FileBuffer = FileBase;
	pPEInfor->FileSize = FileSize;

	this->GetPeInfo(pPEInfor);
}

VOID PeOperation::SetPeOEP(_In_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo)
{
	// 从 dll 中获取到 start 函数，并计算它的页内偏移(加载基址 + 区段基址 + 段内偏移)
	POINTER_TYPE Start = (POINTER_TYPE)GetProcAddress((HMODULE)dllinfo->FileBuffer, "start");
	auto StartOffset = Start - dllinfo->FileBuffer - GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->VirtualAddress;

	// 新的 rav = start 的段内偏移 + 新区段的 rva
	GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->AddressOfEntryPoint = StartOffset +
		GetSectionBase(pPEInfor->FileBuffer, packName.c_str())->VirtualAddress;
}

std::string PeOperation::GetPackDefaultCodeSection(CHAR * FileBuffer)
{
	auto OEP = GET_OPTIONAL_HEADER(FileBuffer)->AddressOfEntryPoint;
	auto count = GET_NT_HEADER(FileBuffer)->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* SecHeader = GET_SECTION_HEADER(FileBuffer);

	for (auto iter = 0; iter < count; iter++) {
		if ((SecHeader[iter].VirtualAddress + SecHeader[iter].SizeOfRawData) > OEP && OEP > SecHeader[iter].VirtualAddress) {	
			return	std::string((char*)SecHeader[iter].Name);
		}
	}
}

PIMAGE_SECTION_HEADER PeOperation::GetSectionBase(POINTER_TYPE Base, LPCSTR SectionName)
{
	// 获取到区段表的第一项
	auto SectionTable = GET_SECTION_HEADER(Base);

	// 获取到区段表的元素个数
	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;

	// 遍历区段表，比较区段的名称，返回区段信息结构体的地址
	for (WORD i = 0; i < SectionCount; ++i)
	{
		// 如果找到就直接返回
		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
			return &SectionTable[i];
	}

	return nullptr;
	
}


VOID PeOperation::PerformBaseRelocation( pPEInfo pPEInfor, pPEInfo dllinfo)
{
	// 重定位项结构体
	struct TypeOffset
	{
		WORD Offset : 12;
		WORD Type : 4;
	};

	auto DllBase = dllinfo->FileBuffer;
	auto FileBase = pPEInfor->FileBuffer;
	DWORD Size = 0, OldProtect = 0;

	// 获取到程序的重定位表
	PIMAGE_DATA_DIRECTORY pDataDirectory = GET_OPTIONAL_HEADER(DllBase)->DataDirectory;
	auto RealocTable = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)DllBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);


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
		for (int i = 0; i < count; i++)
		{
			// 如果 type 的值为 3 我们才需要关注
			if (to[i].Type == 3)
			{
							
				// 获取到需要重定位的地址所在的位置
				POINTER_TYPE* addr = (POINTER_TYPE*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// 计算出不变的段内偏移 = *addr - imagebase - .text va
				POINTER_TYPE item = *addr - DllBase - GetSectionBase(DllBase, dllinfo->DefaultCode.c_str())->VirtualAddress;


				// 使用这个地址，计算出新的重定位后的数据
				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSectionBase(FileBase, packName.c_str())->VirtualAddress;
				
				
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
		RealocTable->VirtualAddress -= GetSectionBase(DllBase, dllinfo->DefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSectionBase(FileBase, packName.c_str())->VirtualAddress;

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((POINTER_TYPE)RealocTable + RealocTable->SizeOfBlock);

	}

	// 关闭程序的重定位，目前只是修复了壳代码的重定位，并不表示源程序支持重定位
	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	GET_FILE_HEADER(FileBase)->Characteristics &= 0xFFFFFFFE;

	//修改重定位表到壳
	pPEInfor->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dllinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	pPEInfor->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dllinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

}

VOID PeOperation::CopySectionData(pPEInfo pPEInfor, pPEInfo dllinfo)
{
	// 获取源区段在虚拟空间(dll->映像)中的基址
	BYTE* SrcData = (BYTE*)(GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->VirtualAddress + dllinfo->FileBuffer);

	// 获取目标区段在虚拟空间(堆->镜像)中的基址
	BYTE* DestData = (BYTE*)(GetSectionBase(pPEInfor->FileBuffer, packName.c_str())->PointerToRawData + pPEInfor->FileBuffer);

	// 直接进行内存拷贝
	memcpy(DestData, SrcData, GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->SizeOfRawData);
}

VOID PeOperation::XorAllSection(pPEInfo pPEInfor, PSHAREDATA Sharedata)
{
	//获取第一个区段
	IMAGE_SECTION_HEADER* pFirstSection = GET_SECTION_HEADER(pPEInfor->FileBuffer);
	Sharedata->index = 0;
	for (int iter = 0; iter < GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections; iter++) {
	
		//跳过资源 只读数据 壳区段
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".rdata");
		DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)packName.c_str());
		DWORD dwIscblt = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".cblt");

		if (dwIsRsrc == 0 || dwIsTls1 == 0 || dwIsTls3 == 0 || dwIscblt == 0) {
			continue;
		}
		else
		{
				
			std::string sTemp(reinterpret_cast<const char*>(pFirstSection[iter].Name));
			// 1. 获取到需要加密的区段的信息
			auto XorSection = GetSectionBase(pPEInfor->FileBuffer, sTemp.c_str());
	
			if (XorSection->SizeOfRawData == 0) {
				continue;
			}
	
			// 2. 找到需要加密的字段所在内存中的位置
			BYTE* data = (BYTE*)(XorSection->PointerToRawData + pPEInfor->FileBuffer);
	
			// 3. 填写解密时需要提供的信息
			srand((unsigned int)time(0));
			Sharedata->key[iter] = rand() % 0xff;
			Sharedata->rva[iter] = XorSection->VirtualAddress;
			Sharedata->size[iter] = XorSection->SizeOfRawData;
			
			// 4. 循环开始进行加密
			for (int i = 0; i < Sharedata->size[iter]; ++i)
			{
				data[i] ^= Sharedata->key[iter];
			}
	
			Sharedata->index += 1;
		}
		
	}
		
}


