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

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		CloseHandle(hFileHandle);
		return FALSE;
	}

	POINTER_TYPE pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));

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
	
	//��PE��Ϣ����PEInformation�ṹ����
	pPEInfor->FileBuffer = (POINTER_TYPE)pFileBuf;
	pPEInfor->FileSize = pFileSize;
	return TRUE;
}


BOOLEAN PeOperation::IsPEFile(UCHAR* pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
	//	MessageBoxA(hwndDlg, "������Ч��MZ��־!", "��ʾ", NULL);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
	//	MessageBoxA(hwndDlg, "������Ч��PE��־!", "��ʾ", NULL);
		return FALSE;
	}
#ifdef _WIN64
	if (pNTHeader->OptionalHeader.Magic != 0x20B)
	{
	//	MessageBoxA(hwndDlg, "������Ч��64λPE����!", "��ʾ", NULL);
		return FALSE;
	}
#else
	if (pNTHeader->OptionalHeader.Magic != 0x10B)
	{
		//MessageBoxA(hwndDlg, "������Ч��32λPE����!", "��ʾ", NULL);
		return FALSE;
	}
#endif // _WIN64



	return TRUE;
}


VOID PeOperation::GetPeInfo(pPEInfo pPEInfor)
{
	auto pFilebuff = pPEInfor->FileBuffer;

	//2.2 ��PE��Ϣ����PEInformation�ṹ����
	pPEInfor->FileBuffer = (POINTER_TYPE)pFilebuff;
	pPEInfor->FileSize = GET_OPTIONAL_HEADER(pFilebuff)->SizeOfImage;
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
	pPEInfor->DataDirectory = GET_OPTIONAL_HEADER(pFilebuff)->DataDirectory;	//Ŀ¼
	pPEInfor->pNtHeader = GET_NT_HEADER(pFilebuff);			//Ntͷ
	pPEInfor->pSectionHeader = GET_SECTION_HEADER(pFilebuff);	//��ͷ
	pPEInfor->OptionalHeader = GET_OPTIONAL_HEADER(pFilebuff);	//��ѡPEͷ
#ifdef _WIN64

#else
	pPEInfor->BaseOfData = GET_OPTIONAL_HEADER(pFilebuff)->BaseOfData;
#endif

	//�ж��ļ���λ
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

	// 1. ��ȡ�����α�����һ��Ԫ�صĵ�ַ
	auto LastSection = &GET_SECTION_HEADER(pPEInfor->FileBuffer)
		[GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections - 1];

	// 2. ���ļ�ͷ�б������������ + 1
	GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections += 1;

	// 3. ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  �� dll ���ҵ�������Ҫ����������
	auto SrcSection = GetSectionBase(Dllpe->FileBuffer, Dllpe->DefaultCode.c_str());

	// 5. ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. �����µ����α��е����ݣ� ����
	memcpy(NewSection->Name, Name.c_str(), 7);

	// 7. �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->SectionAlignment);

	// 8. �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->FileAlignment);

		// 9. ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
	auto FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	auto FileBase = (POINTER_TYPE)realloc((VOID*)pPEInfor->FileBuffer, FileSize);

	// 11. �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
	GET_OPTIONAL_HEADER(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	pPEInfor->FileBuffer = FileBase;
	pPEInfor->FileSize = FileSize;

	this->GetPeInfo(pPEInfor);
}

VOID PeOperation::SetPeOEP(_In_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo)
{
	// �� dll �л�ȡ�� start ����������������ҳ��ƫ��(���ػ�ַ + ���λ�ַ + ����ƫ��)
	POINTER_TYPE Start = (POINTER_TYPE)GetProcAddress((HMODULE)dllinfo->FileBuffer, "start");
	auto StartOffset = Start - dllinfo->FileBuffer - GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->VirtualAddress;

	// �µ� rav = start �Ķ���ƫ�� + �����ε� rva
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

VOID PeOperation::PerformBaseRelocation(_In_ pPEInfo pPEInfor, _In_ pPEInfo dllinfo)
{

	auto dllBase = dllinfo->FileBuffer;
	auto fileBase = pPEInfor->FileBuffer;

	DWORD Size = 0, OldProtect = 0;
	// ��ȡ��������ض�λ��
	PIMAGE_DATA_DIRECTORY pDataDirectory = GET_OPTIONAL_HEADER(dllBase)->DataDirectory;
	auto RealocTable = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)dllBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	
	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + dllBase),
			0x1000, PAGE_READWRITE, &OldProtect);
			
		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		
		WORD* relInfo = (PWORD)((POINTER_TYPE)RealocTable + sizeof(IMAGE_BASE_RELOCATION));

		// ����ÿһ���ض�λ��������
		for (int i = 0; i < count; i++)
		{
			POINTER_TYPE* addr; 
			POINTER_TYPE type, offset, item;

			//the upper 4 bits define the type of relocation
			type = *relInfo >> 12;
			//the lower 12 bits define the offset
			offset = (*relInfo) & 0xFFF;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				
				break;			
			case IMAGE_REL_BASED_HIGHLOW://change comlete 32 bit address					
												// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				addr = (POINTER_TYPE*)(dllBase + RealocTable->VirtualAddress + offset);

				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
				item = *addr - dllBase - GetSectionBase(dllBase, pPEInfor->DefaultCode.c_str())->VirtualAddress;
				// ʹ�������ַ��������µ��ض�λ�������
				*addr = item + GET_OPTIONAL_HEADER(fileBase)->ImageBase + GetSectionBase(fileBase, packName.c_str())->VirtualAddress;
				break;
			default:
				break;
			}
		}
			
		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + dllBase),
			0x1000, OldProtect, &OldProtect);
	
		//-----------------------����VirtualAddress�ֶ�--------------------------------------------
	
		// �ض�λ��VirtualAddress �ֶν����޸ģ���Ҫ���ض�λ���ɿ�д
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, &OldProtect);
	
		// ����VirtualAddress���ӿ��е�text�� Ŀ�����pack��
		// �޸���ʽ ��VirtualAddress - ��.text.VirtualAddress  + Ŀ�����.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSectionBase(dllBase, dllinfo->DefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSectionBase(fileBase, packName.c_str())->VirtualAddress;
	
		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);
	
		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((POINTER_TYPE)RealocTable + RealocTable->SizeOfBlock);
	
	}
	
	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
	GET_OPTIONAL_HEADER(fileBase)->DllCharacteristics = 0;
}

VOID PeOperation::CopySectionData(pPEInfo pPEInfor, pPEInfo dllinfo)
{
	// ��ȡԴ����������ռ�(dll->ӳ��)�еĻ�ַ
	BYTE* SrcData = (BYTE*)(GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->VirtualAddress + dllinfo->FileBuffer);

	// ��ȡĿ������������ռ�(��->����)�еĻ�ַ
	BYTE* DestData = (BYTE*)(GetSectionBase(pPEInfor->FileBuffer, packName.c_str())->PointerToRawData + pPEInfor->FileBuffer);

	// ֱ�ӽ����ڴ濽��
	memcpy(DestData, SrcData, GetSectionBase(dllinfo->FileBuffer, dllinfo->DefaultCode.c_str())->SizeOfRawData);
}

VOID PeOperation::SaveFile(pPEInfo pPEInfor)
{
	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
	HANDLE FileHandle = CreateFileA(FileName.c_str(), GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Write = 0;
	auto tmp = WriteFile(FileHandle, (LPVOID)pPEInfor->FileBuffer, pPEInfor->FileSize, &Write, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);
}
