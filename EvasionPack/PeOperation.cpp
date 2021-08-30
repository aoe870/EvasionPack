#include "PeOperation.h"
#include <iostream>
#include <time.h>
#include "Common.h"
#include <DbgHelp.h>

#define GET_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)(base))
#define GET_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((ULONG_PTR)GET_DOS_HEADER(base)->e_lfanew + (ULONG_PTR)(base)))
#define GET_FILE_HEADER(base) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(base)->FileHeader))
#define GET_OPTIONAL_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(base)->OptionalHeader))
#define GET_SECTION_HEADER( base ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(GET_NT_HEADER(base)) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((GET_NT_HEADER(base)))->FileHeader.SizeOfOptionalHeader   \
    ))


std::string PackTestSection = ".vmp0";	//壳的默认代码段名称(加壳后)
std::string PackDefaultCode = ".text";

// 重定位项结构体
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

/*////////////////////////////////////////////////////////////////
*※※*  FullName:	PerformBaseRelocation
*※※*  功能	:	修复重定位表
*※※*  Returns:	无
*※※*  Parameter:	char* buff,PE文件首地址
*※※*  Parameter:	POINTER_TYPE Value，buff的基址与贴在内存中的地址的差值
*※※*  Parameter:
*※※*  Parameter:
*※※*	Parameter:
*※※*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
//#ifdef _WIN64
void PeOperation::PerformBaseRelocation(POINTER_TYPE buff, POINTER_TYPE Value)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(buff + pDosHeader->e_lfanew);

	//获取目录表头指针
	PIMAGE_DATA_DIRECTORY pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;
	if (pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)buff + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (relocation->VirtualAddress > 0)
		{
			BYTE* dest = (PBYTE)((POINTER_TYPE)buff + relocation->VirtualAddress);
			WORD* relInfo = (PWORD)((POINTER_TYPE)relocation + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); ++i, ++relInfo)
			{
				DWORD* patchAddrHL;
#ifdef _WIN64
				ULONGLONG* patchAddr64;//change comlete 64 bit address
#endif

				POINTER_TYPE type, offset;

				//the upper 4 bits define the type of relocation
				type = *relInfo >> 12;
				//the lower 12 bits define the offset
				offset = (*relInfo) & 0xFFF;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					//skip relocation
					break;
#ifdef _WIN64
				case IMAGE_REL_BASED_DIR64://change comlete 64 bit address
					patchAddr64 = (ULONGLONG*)(dest + offset);
					*patchAddr64 -= Value;
					break;
#endif				
				case IMAGE_REL_BASED_HIGHLOW://change comlete 32 bit address					
					patchAddrHL = (DWORD*)(dest + offset);
					*patchAddrHL -= Value;
					break;
				default:
					break;
				}
			}

			//advance to next relocation block
			relocation = PIMAGE_BASE_RELOCATION((char*)relocation + relocation->SizeOfBlock);
		}
	}

}

/*////////////////////////////////////////////////////////////////
*※※*  FullName:	RebuildImportTable
*※※*  功能	:	修复IAT表
*※※*  Returns:	成功返回1，失败返回0
*※※*  Parameter:	char* buff，PE文件在内存中的地址(拉伸后)
*※※*  Parameter:
*※※*  Parameter:
*※※*  Parameter:
*※※*	Parameter:
*※※*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
BOOL PeOperation::RebuildImportTable(POINTER_TYPE buff)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(buff + pDosHeader->e_lfanew);
	int result = 1;
	//获取目录表头指针
	PIMAGE_DATA_DIRECTORY pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;

	if (pDataDirectory[1].Size > 0)
	{
		//获取导入表地址
		PIMAGE_IMPORT_DESCRIPTOR ImportAddr = PIMAGE_IMPORT_DESCRIPTOR(pDataDirectory[1].VirtualAddress + (POINTER_TYPE)buff);

		for (; !IsBadReadPtr(ImportAddr, sizeof(PIMAGE_IMPORT_DESCRIPTOR)) && ImportAddr->Name; ++ImportAddr)
		{
			POINTER_TYPE* thunkRef;
			FARPROC* funcRef;
#ifdef UNICODE
			HMODULE hModule = LoadLibraryA(LPCSTR(buff + ImportAddr->Name));
#else
			HMODULE hModule = LoadLibrary(LPCSTR(buff + ImportAddr->Name));
#endif // !UNICODE
			//HMODULE hModule = LoadLibrary((buff + ImportAddr->Name));

			if (ImportAddr->OriginalFirstThunk)
			{
				thunkRef = (POINTER_TYPE*)(buff + ImportAddr->OriginalFirstThunk);
				funcRef = (FARPROC*)(buff + ImportAddr->FirstThunk);
			}
			else
			{
				//no hint table
				thunkRef = (POINTER_TYPE*)(buff + ImportAddr->FirstThunk);
				funcRef = (FARPROC*)(buff + ImportAddr->FirstThunk);
			}

			for (; *thunkRef; ++thunkRef, ++funcRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
				{
					*funcRef = (FARPROC)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)(*thunkRef + buff);
					*funcRef = (FARPROC)GetProcAddress(hModule, (LPCSTR)&pFuncName->Name);
				}
				if (*funcRef == 0)
				{
					result = 0;
					break;
				}
			}
		}
	}
	return result;
}


/*////////////////////////////////////////////////////////////////
*※※*  FullName:		GET_HEADER_DICTIONARY
*※※*  功能	:		获取目录表的地址
*※※*  Returns:		成功则返回要查询的那张目录表的内存偏移,表为空则返回0
*※※*  Parameter_1:	module，模块的首地址
*※※*  Parameter_2:	idx,查表的下标
*※※*  Parameter_3:
*※※*  Parameter_4:
*※※*	Parameter_5:
*※※*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
DWORD PeOperation::GET_HEADER_DICTIONARY(POINTER_TYPE module, int idx)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(module + pDosHeader->e_lfanew);

	//获取目录表头指针
	PIMAGE_DATA_DIRECTORY pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;
	if (pDataDirectory[idx].VirtualAddress == 0)
	{
		return 0;
	}
	DWORD res = pDataDirectory[idx].VirtualAddress;

	return res;
}


/*////////////////////////////////////////////////////////////////
*※※*  FullName:		GetPEInformation_
*※※*  功能	:		打开一个文件，拷贝进内存，获取PE文件的各种信息
*※※*  Returns:		成功返回1，失败返回0
*※※*  Parameter_1:	FilePath,文件路径
*※※*  Parameter_2:	pPEInfor，输出参数,把得到的PE信息存放到pPEInfor结构体里
*※※*  Parameter_3:
*※※*  Parameter_4:
*※※*	Parameter_5:
*※※*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
bool PeOperation::GetPEInformation_(TCHAR* FilePath, _Out_ PEInformation* pPEInfor)
{

	//------------------------------------------------------------------------------------
	/////////////////////////////////////////////////////////////
	HANDLE hFileHandle = CreateFile(FilePath, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileHandle == INVALID_HANDLE_VALUE) {
		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
		CloseHandle(hFileHandle);
		return FALSE;
	}

	// 获取文件的大小，并使用这个大小申请缓冲区
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		CloseHandle(hFileHandle);
		return FALSE;
	}

	//auto pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));

	auto pFileBuf = (char *)calloc(pFileSize, sizeof(BYTE));

	// 将目标文件的内容读取到创建的缓冲区中
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

	//2.2 把PE信息存入PEInformation结构体里
	pPEInfor->FileBuffer = (POINTER_TYPE)pFileBuf;
	pPEInfor->FileSize = pFileSize;
	pPEInfor->AddressOfEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
	pPEInfor->BaseOfCode = pNtHeader->OptionalHeader.BaseOfCode;

#ifdef _WIN64

#else
	pPEInfor->BaseOfData = pNtHeader->OptionalHeader.BaseOfData;
#endif

	pPEInfor->pNtHeader = pNtHeader;
	pPEInfor->OptionalHeader = OptionalHeader;
	pPEInfor->pSectionHeader = pSectionHeader;
	pPEInfor->DataDirectory = pNtHeader->OptionalHeader.DataDirectory;
	pPEInfor->e_lfanes = pDosHeader->e_lfanew;
	pPEInfor->FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
	pPEInfor->ImageBase = pNtHeader->OptionalHeader.ImageBase;
	pPEInfor->NumberOfSections = pNtHeader->FileHeader.NumberOfSections;
	pPEInfor->SectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;
	pPEInfor->SizeOfCode = pNtHeader->OptionalHeader.SizeOfCode;
	pPEInfor->SizeOfHeaders = pNtHeader->OptionalHeader.SizeOfHeaders;
	pPEInfor->SizeofImage = pNtHeader->OptionalHeader.SizeOfImage;
	pPEInfor->SizeOfOptionHeaders = pNtHeader->FileHeader.SizeOfOptionalHeader;

	return 1;
}


/*////////////////////////////////////////////////////////////////
*※※*  FullName:		addSeciton
*※※*  功能	:		添加新节
*※※*  Returns:		成功返回1，失败返回0
*※※*  Parameter_1:	pFileBuff，模块地址
*※※*  Parameter_2:	AddSize，要添加的大小
*※※*  Parameter_3:	secname，新节名称，限制在八个字节内
*※※*  Parameter_4:
*※※*	Parameter_5:
*※※*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
bool PeOperation::addSeciton(POINTER_TYPE pFileBuff, DWORD AddSize, char secname[8])
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuff + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((POINTER_TYPE)pFileBuff + pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((POINTER_TYPE)OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	//判断节表尾部是否有80个字节的空闲区域
	PIMAGE_SECTION_HEADER pse_temp = pSectionHeader + pNtHeader->FileHeader.NumberOfSections;//节表新增节的首地址
	PIMAGE_SECTION_HEADER pse_temp_b = pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;//节表最后一节的首地址
	int space = OptionalHeader->SizeOfHeaders - ((POINTER_TYPE)pse_temp - (POINTER_TYPE)pFileBuff);

	//space空间指的是节表最后都是0,没有其他数据，如果有其他数据，则即使满足了有80个字节的空间，也不能添加数据，这样会破坏其他数据
	//如果空间不够,那么，doc头下面的垃圾数据不要了，后面的PE头 标准PE头 和节表上提;
	//并且要判断pDosHeader->e_lfanew-64这段距离是否大于80，否则上提没有意义
	if (pDosHeader->e_lfanew - 64 > 80 && space < 80)
	{
		int len = ((POINTER_TYPE*)pse_temp - (POINTER_TYPE*)&(pNtHeader->Signature)) * 4;
		for (int i = 0; i < len; i++)
		{
			*((char*)pFileBuff + 64 + i) = *((char*)pFileBuff + i + pDosHeader->e_lfanew);
		}
		pDosHeader->e_lfanew = 0x40;

		pse_temp = pSectionHeader + pNtHeader->FileHeader.NumberOfSections;
		pse_temp_b = pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;
		for (int i = 0; i < 80; i++)//把节表尾部80个字节格式化
			*((char*)pFileBuff + 64 + i + len) = 0;
		space = pDosHeader->e_lfanew - 64;//更新space空间
	}
	if (space > 80)
	{
		BYTE(*p)[8] = &(pse_temp->Name);

		for (int i = 0; i < strlen(secname); i++)
		{
			p[0][i] = secname[i];
		}

		pse_temp->Misc.VirtualSize = AddSize;

		if (pse_temp_b->Misc.VirtualSize > pse_temp_b->SizeOfRawData)//比较内存大小和文件大小
		{
			//检测内存大小是否对齐
			pse_temp->VirtualAddress =
				((pse_temp_b->Misc.VirtualSize % OptionalHeader->SectionAlignment) == 0) ? (pse_temp_b->Misc.VirtualSize + pse_temp_b->VirtualAddress) :
				(pse_temp_b->Misc.VirtualSize - pse_temp_b->Misc.VirtualSize % OptionalHeader->SectionAlignment + OptionalHeader->SectionAlignment) +
				pse_temp_b->VirtualAddress;
			printf("%X\n", *&(pse_temp->VirtualAddress));
		}
		else
		{
			pse_temp->VirtualAddress =
				((pse_temp_b->SizeOfRawData % OptionalHeader->SectionAlignment) == 0) ? (pse_temp_b->SizeOfRawData + pse_temp_b->VirtualAddress) :
				(pse_temp_b->SizeOfRawData - pse_temp_b->SizeOfRawData % OptionalHeader->SectionAlignment + OptionalHeader->SectionAlignment) +
				pse_temp_b->VirtualAddress;
		}

		pse_temp->SizeOfRawData = AddSize;
		pse_temp->PointerToRawData = pse_temp_b->SizeOfRawData + pse_temp_b->PointerToRawData;
		pse_temp->Characteristics = 0xE0000020;
		pNtHeader->FileHeader.NumberOfSections = pNtHeader->FileHeader.NumberOfSections + 1;
		pNtHeader->OptionalHeader.SizeOfImage = pNtHeader->OptionalHeader.SizeOfImage + AddSize;
	}
	else
	{
		printf("添加节失败,没有空间添加新的节!");
		return false;
	}

	return true;
}


////////////////////////////////////////////////////////////
/// <summary>
/// 加载PE文件
/// </summary>
/// <param name="FileName">文件路径</param>
/// <param name="Peinfo"></param>
/// <returns></returns>
BOOLEAN PeOperation::LoadExeFile(TCHAR* FileName, _Out_ PEInformation* Peinfo)
{
	// 如果文件存在，就打开文件，打开的目的只是为了读取其中的数据
	HANDLE hFileHandle = CreateFile(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileHandle == INVALID_HANDLE_VALUE) {
		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
		return false;
	}

	// 获取文件的大小，并使用这个大小申请缓冲区
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		return false;
	}

	auto pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Read = 0;
	ReadFile(hFileHandle, (LPVOID)pFileBuf, pFileSize, &Read, NULL);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(hFileHandle);

	//填充信息
	Peinfo->FileBuffer = pFileBuf;
	Peinfo->FileSize = pFileSize;
	return true;
}


BOOLEAN PeOperation::IsPEFile(POINTER_TYPE pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBoxA(NULL, "不是有效的MZ标志!", "提示", NULL);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, "不是有效的PE标志!", "提示", NULL);
		return FALSE;
	}
#ifdef _WIN64
	if (pNTHeader->OptionalHeader.Magic != 0x20B)
	{
		MessageBoxA(NULL, "不是有效的64位PE程序!", "提示", NULL);
		return FALSE;
	}
#else
	if (pNTHeader->OptionalHeader.Magic != 0x10B)
	{
		MessageBoxA(NULL, "不是有效的32位PE程序!", "提示", NULL);
		return FALSE;
	}
#endif // _WIN64

	return TRUE;
}

BOOLEAN PeOperation::GetPeInfo(POINTER_TYPE Base, PEInformation* Peinfo)
{

	//PE文件头地址
	Peinfo->e_lfanes = GET_DOS_HEADER(Base)->e_lfanew;
	//区段数目
	Peinfo->NumberOfSections = GET_FILE_HEADER(Base)->NumberOfSections;
	//可选头大小
	Peinfo->SizeOfOptionHeaders = GET_FILE_HEADER(Base)->SizeOfOptionalHeader;
	//代码节大小
	Peinfo->SizeOfCode = GET_OPTIONAL_HEADER(Base)->SizeOfCode;
	//OEP(RVA)入口点
	Peinfo->AddressOfEntryPoint = GET_OPTIONAL_HEADER(Base)->AddressOfEntryPoint;
	//代码基址
	Peinfo->BaseOfCode = GET_OPTIONAL_HEADER(Base)->BaseOfCode;

	//镜像基址
	Peinfo->ImageBase = GET_OPTIONAL_HEADER(Base)->ImageBase;
	//内存对齐
	Peinfo->SectionAlignment = GET_OPTIONAL_HEADER(Base)->SectionAlignment;
	//文件对齐
	Peinfo->FileAlignment = GET_OPTIONAL_HEADER(Base)->FileAlignment;
	//镜像大小
	Peinfo->SizeofImage = GET_OPTIONAL_HEADER(Base)->SizeOfImage;
	//头大小
	Peinfo->SizeOfHeaders = GET_OPTIONAL_HEADER(Base)->SizeOfHeaders;
	//目录
	Peinfo->DataDirectory = GET_OPTIONAL_HEADER(Base)->DataDirectory;
	//Nt头
	Peinfo->pNtHeader = GET_NT_HEADER(Base);
	//节头
	Peinfo->pSectionHeader = GET_SECTION_HEADER(Base);
	//可选PE头
	Peinfo->OptionalHeader = GET_OPTIONAL_HEADER(Base);


#ifdef _WIN64

#else
	Peinfo->BaseOfData = GET_OPTIONAL_HEADER(Base)->BaseOfData;
#endif
	return true;
}

void PeOperation::SaveFile(PEInformation Peinfo)
{
	// 无论文件是否存在，都要创建新的文件
	HANDLE FileHandle = CreateFileA("../output/test_Demo.exe", GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Write = 0;
	auto tmp = WriteFile(FileHandle, (LPVOID)Peinfo.FileBuffer, Peinfo.SizeofImage, &Write, NULL);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(FileHandle);
}


void PeOperation::AddSection(POINTER_TYPE Base, POINTER_TYPE DllBase, PEInformation *Peinfo)
{
	auto Alignment = [](DWORD n, DWORD align)
	{
		return n % align == 0 ? n : (n / align + 1) * align;
	};

	// 1. 获取到区段表的最后一个元素的地址
	auto LastSection = &GET_SECTION_HEADER(Base)
		[GET_FILE_HEADER(Base)->NumberOfSections - 1];

	// 2. 将文件头中保存的区段数量 + 1
	GET_FILE_HEADER(Base)->NumberOfSections += 1;

	// 3. 通过最后一个区段，找到新添加的区段的位置
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  从 dll 中找到我们需要拷贝的区段
	auto SrcSection = GetSection(DllBase, PackDefaultCode.c_str());

	// 5. 直接将源区段的完整信息拷贝到新的区段中
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. 设置新的区段表中的数据： 名称
	memcpy(NewSection->Name, PackTestSection.c_str(), 7);

	// 7. 设置新的区段所在的 RVA = 上一个区段的RVA + 对齐的内存大小
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(Base)->SectionAlignment);

	// 8. 设置新的区段所在的 FOA = 上一个区段的FOA + 对齐的文件大小
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(Base)->FileAlignment);

	// 9. 重新计算文件的大小，申请新的空间保存原有的数据
	Peinfo->FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	Peinfo->FileBuffer = (DWORD)realloc((VOID*)Base, Peinfo->FileSize);

	// 11. 修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小
	GET_OPTIONAL_HEADER(Peinfo->FileBuffer)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

}

PIMAGE_SECTION_HEADER PeOperation::GetSection(POINTER_TYPE Base, LPCSTR SectionName)
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


/// <summary>
/// 
/// </summary>
VOID  PeOperation::FixReloc(POINTER_TYPE Base, POINTER_TYPE DllBase)
{

	PULONG Size = 0, OldProtect = 0;

	// 获取到程序的重定位表
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, Size);

	// 如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock)
	{
		// 如果重定位的数据在代码段，就需要修改访问属性
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, PAGE_READWRITE, OldProtect);

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
				DWORD* addr = (DWORD*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// 计算出不变的段内偏移 = *addr - imagebase - .text va
				DWORD item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

				// 使用这个地址，计算出新的重定位后的数据
				*addr = item + GET_OPTIONAL_HEADER(Base)->ImageBase + GetSection(Base, PackTestSection.c_str())->VirtualAddress;
				// printf("\t%08x - %08X - %08X\n", addr, *addr, item);
			}
		}

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, *OldProtect, OldProtect);


		//-----------------------修正VirtualAddress字段--------------------------------------------

		// 重定位中VirtualAddress 字段进行修改，需要把重定位表变成可写
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, OldProtect);

		// 修正VirtualAddress，从壳中的text到 目标程序pack段
		// 修复公式 ：VirtualAddress - 壳.text.VirtualAddress  + 目标程序.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(Base, PackTestSection.c_str())->VirtualAddress;

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, *OldProtect, OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	// 关闭程序的重定位，目前只是修复了壳代码的重定位，并不表示源程序支持重定位
	GET_OPTIONAL_HEADER(Base)->DllCharacteristics = 0;

}


/// <summary>
/// 填充新区段内容
/// </summary>
/// <param name="SectionName"></param>
/// <param name="SrcName"></param>
VOID PeOperation::CopySectionData(POINTER_TYPE Base, POINTER_TYPE DllBase)
{
	// 获取源区段在虚拟空间(dll->映像)中的基址
	BYTE* SrcData = (BYTE*)(GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress + DllBase);

	// 获取目标区段在虚拟空间(堆->镜像)中的基址
	BYTE* DestData = (BYTE*)(GetSection(Base, PackTestSection.c_str())->PointerToRawData + Base);

	// 直接进行内存拷贝
	memcpy(DestData, SrcData, GetSection(DllBase, PackDefaultCode.c_str())->SizeOfRawData);
}