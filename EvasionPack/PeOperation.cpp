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


std::string PackTestSection = ".vmp0";	//�ǵ�Ĭ�ϴ��������(�ӿǺ�)
std::string PackDefaultCode = ".text";

// �ض�λ��ṹ��
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

/*////////////////////////////////////////////////////////////////
*����*  FullName:	PerformBaseRelocation
*����*  ����	:	�޸��ض�λ��
*����*  Returns:	��
*����*  Parameter:	char* buff,PE�ļ��׵�ַ
*����*  Parameter:	POINTER_TYPE Value��buff�Ļ�ַ�������ڴ��еĵ�ַ�Ĳ�ֵ
*����*  Parameter:
*����*  Parameter:
*����*	Parameter:
*����*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
//#ifdef _WIN64
void PeOperation::PerformBaseRelocation(POINTER_TYPE buff, POINTER_TYPE Value)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(buff + pDosHeader->e_lfanew);

	//��ȡĿ¼��ͷָ��
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
*����*  FullName:	RebuildImportTable
*����*  ����	:	�޸�IAT��
*����*  Returns:	�ɹ�����1��ʧ�ܷ���0
*����*  Parameter:	char* buff��PE�ļ����ڴ��еĵ�ַ(�����)
*����*  Parameter:
*����*  Parameter:
*����*  Parameter:
*����*	Parameter:
*����*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
BOOL PeOperation::RebuildImportTable(POINTER_TYPE buff)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(buff + pDosHeader->e_lfanew);
	int result = 1;
	//��ȡĿ¼��ͷָ��
	PIMAGE_DATA_DIRECTORY pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;

	if (pDataDirectory[1].Size > 0)
	{
		//��ȡ������ַ
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
*����*  FullName:		GET_HEADER_DICTIONARY
*����*  ����	:		��ȡĿ¼��ĵ�ַ
*����*  Returns:		�ɹ��򷵻�Ҫ��ѯ������Ŀ¼����ڴ�ƫ��,��Ϊ���򷵻�0
*����*  Parameter_1:	module��ģ����׵�ַ
*����*  Parameter_2:	idx,�����±�
*����*  Parameter_3:
*����*  Parameter_4:
*����*	Parameter_5:
*����*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
DWORD PeOperation::GET_HEADER_DICTIONARY(POINTER_TYPE module, int idx)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(module + pDosHeader->e_lfanew);

	//��ȡĿ¼��ͷָ��
	PIMAGE_DATA_DIRECTORY pDataDirectory = pNtHeader->OptionalHeader.DataDirectory;
	if (pDataDirectory[idx].VirtualAddress == 0)
	{
		return 0;
	}
	DWORD res = pDataDirectory[idx].VirtualAddress;

	return res;
}


/*////////////////////////////////////////////////////////////////
*����*  FullName:		GetPEInformation_
*����*  ����	:		��һ���ļ����������ڴ棬��ȡPE�ļ��ĸ�����Ϣ
*����*  Returns:		�ɹ�����1��ʧ�ܷ���0
*����*  Parameter_1:	FilePath,�ļ�·��
*����*  Parameter_2:	pPEInfor���������,�ѵõ���PE��Ϣ��ŵ�pPEInfor�ṹ����
*����*  Parameter_3:
*����*  Parameter_4:
*����*	Parameter_5:
*����*	Author:		    LCH
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

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		CloseHandle(hFileHandle);
		return FALSE;
	}

	//auto pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));

	auto pFileBuf = (char *)calloc(pFileSize, sizeof(BYTE));

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Read = 0;
	ReadFile(hFileHandle, (LPVOID)pFileBuf, pFileSize, &Read, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(hFileHandle);

	//2.1 �ж��Ƿ�ΪPE�ļ�
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBoxA(NULL, "����MZ��ͷ", "��ʾ", MB_OK);
		return 0;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((POINTER_TYPE)pFileBuf + pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((POINTER_TYPE)OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, "����PE�ļ�", "��ʾ", MB_OK);
		return 0;
	}

	//2.2 ��PE��Ϣ����PEInformation�ṹ����
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
*����*  FullName:		addSeciton
*����*  ����	:		����½�
*����*  Returns:		�ɹ�����1��ʧ�ܷ���0
*����*  Parameter_1:	pFileBuff��ģ���ַ
*����*  Parameter_2:	AddSize��Ҫ��ӵĴ�С
*����*  Parameter_3:	secname���½����ƣ������ڰ˸��ֽ���
*����*  Parameter_4:
*����*	Parameter_5:
*����*	Author:		    LCH
*/////////////////////////////////////////////////////////////////;
bool PeOperation::addSeciton(POINTER_TYPE pFileBuff, DWORD AddSize, char secname[8])
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuff + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((POINTER_TYPE)pFileBuff + pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((POINTER_TYPE)OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	//�жϽڱ�β���Ƿ���80���ֽڵĿ�������
	PIMAGE_SECTION_HEADER pse_temp = pSectionHeader + pNtHeader->FileHeader.NumberOfSections;//�ڱ������ڵ��׵�ַ
	PIMAGE_SECTION_HEADER pse_temp_b = pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;//�ڱ����һ�ڵ��׵�ַ
	int space = OptionalHeader->SizeOfHeaders - ((POINTER_TYPE)pse_temp - (POINTER_TYPE)pFileBuff);

	//space�ռ�ָ���ǽڱ������0,û���������ݣ�������������ݣ���ʹ��������80���ֽڵĿռ䣬Ҳ����������ݣ��������ƻ���������
	//����ռ䲻��,��ô��docͷ������������ݲ�Ҫ�ˣ������PEͷ ��׼PEͷ �ͽڱ�����;
	//����Ҫ�ж�pDosHeader->e_lfanew-64��ξ����Ƿ����80����������û������
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
		for (int i = 0; i < 80; i++)//�ѽڱ�β��80���ֽڸ�ʽ��
			*((char*)pFileBuff + 64 + i + len) = 0;
		space = pDosHeader->e_lfanew - 64;//����space�ռ�
	}
	if (space > 80)
	{
		BYTE(*p)[8] = &(pse_temp->Name);

		for (int i = 0; i < strlen(secname); i++)
		{
			p[0][i] = secname[i];
		}

		pse_temp->Misc.VirtualSize = AddSize;

		if (pse_temp_b->Misc.VirtualSize > pse_temp_b->SizeOfRawData)//�Ƚ��ڴ��С���ļ���С
		{
			//����ڴ��С�Ƿ����
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
		printf("��ӽ�ʧ��,û�пռ�����µĽ�!");
		return false;
	}

	return true;
}


////////////////////////////////////////////////////////////
/// <summary>
/// ����PE�ļ�
/// </summary>
/// <param name="FileName">�ļ�·��</param>
/// <param name="Peinfo"></param>
/// <returns></returns>
BOOLEAN PeOperation::LoadExeFile(TCHAR* FileName, _Out_ PEInformation* Peinfo)
{
	// ����ļ����ڣ��ʹ��ļ����򿪵�Ŀ��ֻ��Ϊ�˶�ȡ���е�����
	HANDLE hFileHandle = CreateFile(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileHandle == INVALID_HANDLE_VALUE) {
		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
		return false;
	}

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		return false;
	}

	auto pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Read = 0;
	ReadFile(hFileHandle, (LPVOID)pFileBuf, pFileSize, &Read, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(hFileHandle);

	//�����Ϣ
	Peinfo->FileBuffer = pFileBuf;
	Peinfo->FileSize = pFileSize;
	return true;
}


BOOLEAN PeOperation::IsPEFile(POINTER_TYPE pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBoxA(NULL, "������Ч��MZ��־!", "��ʾ", NULL);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, "������Ч��PE��־!", "��ʾ", NULL);
		return FALSE;
	}
#ifdef _WIN64
	if (pNTHeader->OptionalHeader.Magic != 0x20B)
	{
		MessageBoxA(NULL, "������Ч��64λPE����!", "��ʾ", NULL);
		return FALSE;
	}
#else
	if (pNTHeader->OptionalHeader.Magic != 0x10B)
	{
		MessageBoxA(NULL, "������Ч��32λPE����!", "��ʾ", NULL);
		return FALSE;
	}
#endif // _WIN64

	return TRUE;
}

BOOLEAN PeOperation::GetPeInfo(POINTER_TYPE Base, PEInformation* Peinfo)
{

	//PE�ļ�ͷ��ַ
	Peinfo->e_lfanes = GET_DOS_HEADER(Base)->e_lfanew;
	//������Ŀ
	Peinfo->NumberOfSections = GET_FILE_HEADER(Base)->NumberOfSections;
	//��ѡͷ��С
	Peinfo->SizeOfOptionHeaders = GET_FILE_HEADER(Base)->SizeOfOptionalHeader;
	//����ڴ�С
	Peinfo->SizeOfCode = GET_OPTIONAL_HEADER(Base)->SizeOfCode;
	//OEP(RVA)��ڵ�
	Peinfo->AddressOfEntryPoint = GET_OPTIONAL_HEADER(Base)->AddressOfEntryPoint;
	//�����ַ
	Peinfo->BaseOfCode = GET_OPTIONAL_HEADER(Base)->BaseOfCode;

	//�����ַ
	Peinfo->ImageBase = GET_OPTIONAL_HEADER(Base)->ImageBase;
	//�ڴ����
	Peinfo->SectionAlignment = GET_OPTIONAL_HEADER(Base)->SectionAlignment;
	//�ļ�����
	Peinfo->FileAlignment = GET_OPTIONAL_HEADER(Base)->FileAlignment;
	//�����С
	Peinfo->SizeofImage = GET_OPTIONAL_HEADER(Base)->SizeOfImage;
	//ͷ��С
	Peinfo->SizeOfHeaders = GET_OPTIONAL_HEADER(Base)->SizeOfHeaders;
	//Ŀ¼
	Peinfo->DataDirectory = GET_OPTIONAL_HEADER(Base)->DataDirectory;
	//Ntͷ
	Peinfo->pNtHeader = GET_NT_HEADER(Base);
	//��ͷ
	Peinfo->pSectionHeader = GET_SECTION_HEADER(Base);
	//��ѡPEͷ
	Peinfo->OptionalHeader = GET_OPTIONAL_HEADER(Base);


#ifdef _WIN64

#else
	Peinfo->BaseOfData = GET_OPTIONAL_HEADER(Base)->BaseOfData;
#endif
	return true;
}

void PeOperation::SaveFile(PEInformation Peinfo)
{
	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
	HANDLE FileHandle = CreateFileA("../output/test_Demo.exe", GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Write = 0;
	auto tmp = WriteFile(FileHandle, (LPVOID)Peinfo.FileBuffer, Peinfo.SizeofImage, &Write, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);
}


void PeOperation::AddSection(POINTER_TYPE Base, POINTER_TYPE DllBase, PEInformation *Peinfo)
{
	auto Alignment = [](DWORD n, DWORD align)
	{
		return n % align == 0 ? n : (n / align + 1) * align;
	};

	// 1. ��ȡ�����α�����һ��Ԫ�صĵ�ַ
	auto LastSection = &GET_SECTION_HEADER(Base)
		[GET_FILE_HEADER(Base)->NumberOfSections - 1];

	// 2. ���ļ�ͷ�б������������ + 1
	GET_FILE_HEADER(Base)->NumberOfSections += 1;

	// 3. ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  �� dll ���ҵ�������Ҫ����������
	auto SrcSection = GetSection(DllBase, PackDefaultCode.c_str());

	// 5. ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. �����µ����α��е����ݣ� ����
	memcpy(NewSection->Name, PackTestSection.c_str(), 7);

	// 7. �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(Base)->SectionAlignment);

	// 8. �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(Base)->FileAlignment);

	// 9. ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
	Peinfo->FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	Peinfo->FileBuffer = (DWORD)realloc((VOID*)Base, Peinfo->FileSize);

	// 11. �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
	GET_OPTIONAL_HEADER(Peinfo->FileBuffer)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

}

PIMAGE_SECTION_HEADER PeOperation::GetSection(POINTER_TYPE Base, LPCSTR SectionName)
{
	// 1. ��ȡ�����α�ĵ�һ��
	auto SectionTable = GET_SECTION_HEADER(Base);

	// 2. ��ȡ�����α��Ԫ�ظ���
	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;

	// 3. �������α��Ƚ����ε����ƣ�����������Ϣ�ṹ��ĵ�ַ
	for (WORD i = 0; i < SectionCount; ++i)
	{
		// ����ҵ���ֱ�ӷ���
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

	// ��ȡ��������ض�λ��
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, Size);

	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, PAGE_READWRITE, OldProtect);

		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// ����ÿһ���ض�λ��������
		for (int i = 0; i < count; i++)
		{
			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
			if (to[i].Type == 3)
			{
				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				DWORD* addr = (DWORD*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
				DWORD item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

				// ʹ�������ַ��������µ��ض�λ�������
				*addr = item + GET_OPTIONAL_HEADER(Base)->ImageBase + GetSection(Base, PackTestSection.c_str())->VirtualAddress;
				// printf("\t%08x - %08X - %08X\n", addr, *addr, item);
			}
		}

		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, *OldProtect, OldProtect);


		//-----------------------����VirtualAddress�ֶ�--------------------------------------------

		// �ض�λ��VirtualAddress �ֶν����޸ģ���Ҫ���ض�λ���ɿ�д
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, OldProtect);

		// ����VirtualAddress���ӿ��е�text�� Ŀ�����pack��
		// �޸���ʽ ��VirtualAddress - ��.text.VirtualAddress  + Ŀ�����.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(Base, PackTestSection.c_str())->VirtualAddress;

		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, *OldProtect, OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
	GET_OPTIONAL_HEADER(Base)->DllCharacteristics = 0;

}


/// <summary>
/// �������������
/// </summary>
/// <param name="SectionName"></param>
/// <param name="SrcName"></param>
VOID PeOperation::CopySectionData(POINTER_TYPE Base, POINTER_TYPE DllBase)
{
	// ��ȡԴ����������ռ�(dll->ӳ��)�еĻ�ַ
	BYTE* SrcData = (BYTE*)(GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress + DllBase);

	// ��ȡĿ������������ռ�(��->����)�еĻ�ַ
	BYTE* DestData = (BYTE*)(GetSection(Base, PackTestSection.c_str())->PointerToRawData + Base);

	// ֱ�ӽ����ڴ濽��
	memcpy(DestData, SrcData, GetSection(DllBase, PackDefaultCode.c_str())->SizeOfRawData);
}