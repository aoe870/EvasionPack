#include "PeOperation.h"
#include "lz4.h"
#include <time.h>
#include "AES.h"

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
		PrintLog("open file error !", LOGTRPE_ERROR);
		return FALSE;
	}

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	auto pFileSize = GetFileSize(hFileHandle, NULL);
	if (pFileSize == 0xFFFFFFFF) {
		CloseHandle(hFileHandle);
		PrintLog("Memory allocation failed!", LOGTRPE_ERROR);
		return FALSE;
	}
	//POINTER_TYPE pFileBuf = (POINTER_TYPE)malloc(pFileSize + 100);
	POINTER_TYPE pFileBuf = (POINTER_TYPE)calloc(pFileSize, sizeof(BYTE));
	//POINTER_TYPE pFileBuf = (POINTER_TYPE)m_alloc.auto_malloc<CHAR*>(pFileSize);

	DWORD Read = 0;
	if (!ReadFile(hFileHandle, (LPVOID)pFileBuf, pFileSize, &Read, NULL)) {
		PrintLog("Open Pe file failed!", LOGTRPE_ERROR);
		return FALSE;
	};
	 
	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(hFileHandle);
	 
	//2.1 �ж��Ƿ�ΪPE�ļ�
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PrintLog("The file does not begin with MZ", LOGTRPE_ERROR);
		return 0;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((POINTER_TYPE)pFileBuf + pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((POINTER_TYPE)OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		PrintLog("Not PE file", LOGTRPE_ERROR);
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
		PrintLog("Not a valid MZ flag", LOGTRPE_ERROR);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
	//	MessageBoxA(hwndDlg, "������Ч��PE��־!", "��ʾ", NULL);
		PrintLog("Not a valid MZ flag", LOGTRPE_ERROR);
		return FALSE;
	}
#ifdef _WIN64
	if (pNTHeader->OptionalHeader.Magic != 0x20B)
	{
	//	MessageBoxA(hwndDlg, "������Ч��64λPE����!", "��ʾ", NULL);
		PrintLog("Not a valid 64-bit PE App", LOGTRPE_ERROR);
		return FALSE;
	}
#else
	if (pNTHeader->OptionalHeader.Magic != 0x10B)
	{
		//MessageBoxA(hwndDlg, "������Ч��32λPE����!", "��ʾ", NULL);
		PrintLog("Not a valid 32-bit PE App ", LOGTRPE_ERROR);
		return FALSE;
	}
#endif // _WIN64

	return TRUE;
}


VOID PeOperation::GetPeInfo(pPEInfo pPEInfor)
{
	auto pFilebuff = pPEInfor->FileBuffer;

	//2.2 ��PE��Ϣ����PEInformation�ṹ����
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

	pPEInfor->DefaultCode = GetPackDefaultCodeSection((CHAR*)pPEInfor->FileBuffer);
}

VOID PeOperation::AddSection(_In_ pPEInfo pPEInfor, _In_ pPEInfo Dllpe, std::string Name)
{

	packName = Name;

	// ��ȡ�����α�����һ��Ԫ�صĵ�ַ
	auto LastSection = &GET_SECTION_HEADER(pPEInfor->FileBuffer)
		[GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections - 1];

	// ���ļ�ͷ�б������������ + 1
	GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections += 1;

	// ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// �� dll ���ҵ�������Ҫ����������
	auto SrcSection = GetSectionBase(Dllpe->FileBuffer, Dllpe->DefaultCode.c_str());

	// ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// �����µ����α��е����ݣ� ����
	memset(NewSection->Name, 0, 7);
	memcpy(NewSection->Name, Name.c_str(), Name.size());

	// �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->SectionAlignment);

	// �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(pPEInfor->FileBuffer)->FileAlignment);

		// ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
	auto FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	auto FileBase = (POINTER_TYPE)realloc((VOID*)pPEInfor->FileBuffer, FileSize);

	// �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
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

	for (auto iter = 0; iter < count - 1; iter++) {
		if (SecHeader[iter].VirtualAddress <= OEP && OEP <= SecHeader[iter + 1].VirtualAddress) {	
			return	std::string((char*)SecHeader[iter].Name);
		}
	}
}

PIMAGE_SECTION_HEADER PeOperation::GetSectionBase(POINTER_TYPE Base, LPCSTR SectionName)
{
	// ��ȡ�����α�ĵ�һ��
	auto SectionTable = GET_SECTION_HEADER(Base);

	// ��ȡ�����α��Ԫ�ظ���
	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;

	// �������α��Ƚ����ε����ƣ�����������Ϣ�ṹ��ĵ�ַ
	for (WORD i = 0; i < SectionCount; ++i)
	{
		// ����ҵ���ֱ�ӷ���
		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
			return &SectionTable[i];
	}

	return nullptr;
	
}


VOID PeOperation::PerformBaseRelocation( pPEInfo pPEInfor, pPEInfo dllinfo)
{
	// �ض�λ��ṹ��
	struct TypeOffset
	{
		WORD Offset : 12;
		WORD Type : 4;
	};

	auto DllBase = dllinfo->FileBuffer;
	auto FileBase = pPEInfor->FileBuffer;
	DWORD Size = 0, OldProtect = 0;

	// ��ȡ��������ض�λ��
	PIMAGE_DATA_DIRECTORY pDataDirectory = GET_OPTIONAL_HEADER(DllBase)->DataDirectory;
	auto RealocTable = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)DllBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);


	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
	
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, PAGE_READWRITE, &OldProtect);
		
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
				POINTER_TYPE* addr = (POINTER_TYPE*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
				POINTER_TYPE item = *addr - DllBase - GetSectionBase(DllBase, dllinfo->DefaultCode.c_str())->VirtualAddress;


				// ʹ�������ַ��������µ��ض�λ�������
				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSectionBase(FileBase, packName.c_str())->VirtualAddress;
				
				
			}
		}
		
		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, OldProtect, &OldProtect);


		//-----------------------����VirtualAddress�ֶ�--------------------------------------------

		// �ض�λ��VirtualAddress �ֶν����޸ģ���Ҫ���ض�λ���ɿ�д
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, &OldProtect);

		// ����VirtualAddress���ӿ��е�text�� Ŀ�����pack��
		// �޸���ʽ ��VirtualAddress - ��.text.VirtualAddress  + Ŀ�����.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSectionBase(DllBase, dllinfo->DefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSectionBase(FileBase, packName.c_str())->VirtualAddress;

		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((POINTER_TYPE)RealocTable + RealocTable->SizeOfBlock);

	}

	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics = 0;

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

VOID PeOperation::XorAllSection(pPEInfo pPEInfor, PSHAREDATA Sharedata)
{
	//��ȡ��һ������
	IMAGE_SECTION_HEADER* pFirstSection = GET_SECTION_HEADER(pPEInfor->FileBuffer);
	Sharedata->index = 0;
	for (int iter = 0; iter < GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections; iter++) {
	
		//������Դ ֻ������ ������
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".text");
		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".data");
		//DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)packName.c_str());
		//DWORD dwIscblt = lstrcmp((LPCWSTR)pFirstSection[iter].Name, (LPCWSTR)".cblt");

		if (dwIsRsrc == 0 || dwIsTls3 == 0) {
			
			std::string sTemp(reinterpret_cast<const char*>(pFirstSection[iter].Name));
			// 1. ��ȡ����Ҫ���ܵ����ε���Ϣ
			auto XorSection = GetSectionBase(pPEInfor->FileBuffer, sTemp.c_str());

			if (XorSection->SizeOfRawData == 0) {
				continue;
			}

			// 2. �ҵ���Ҫ���ܵ��ֶ������ڴ��е�λ��
			BYTE* data = (BYTE*)(XorSection->PointerToRawData + pPEInfor->FileBuffer);

			// 3. ��д����ʱ��Ҫ�ṩ����Ϣ
			srand((unsigned int)time(0));
			Sharedata->key[iter] = rand() % 0xff;
			Sharedata->rva[iter] = XorSection->VirtualAddress;
			Sharedata->size[iter] = XorSection->SizeOfRawData;

			// 4. ѭ����ʼ���м���
			for (int i = 0; i < Sharedata->size[iter]; ++i)
			{
				data[i] ^= Sharedata->key[iter];
			}

			Sharedata->index += 1;
		}
		else
		{				
			continue;
		}		
	}		
}

VOID PeOperation::CompressSection(pPEInfo pPEInfor, PSHAREDATA data)
{
	// ��ȡ���������Ϣ
	PIMAGE_SECTION_HEADER pSection = GetSectionBase(pPEInfor->FileBuffer, pPEInfor->DefaultCode.c_str());
	// ѹ��ǰλ��
	char* pRoffset = (char*)(pSection->PointerToRawData + pPEInfor->FileBuffer);
	// �������ļ��еĴ�С
	long lSize = pSection->SizeOfRawData;

	// ����ѹ��ǰ��Ϣ
	// ѹ�����ݵ�RVA
	data->FrontCompressRva = pSection->VirtualAddress;
	// ѹ��ǰ��СSize
	data->FrontCompressSize = lSize;

	// ---------------------------------��ʼѹ��
	// ��ȡԤ����ѹ������ֽ���:
	int compress_size = LZ4_compressBound(lSize);
	// �����ڴ�ռ�, ���ڱ���ѹ���������
	char* pBuff = new char[compress_size];
	//  ��ʼѹ���ļ�����(��������ѹ����Ĵ�С)
	data->LaterCompressSize = LZ4_compress(
		pRoffset,/*ѹ��ǰ������*/
		pBuff, /*ѹ���������*/
		lSize/*�ļ�ԭʼ��С*/);

	memset(pRoffset, 0, pSection->SizeOfRawData);

	// ��ѹ��������ݸ���ԭʼ����
	memcpy(pRoffset, pBuff, data->LaterCompressSize);

	// �ͷſռ�
	delete[]pBuff;
}


ENCRYPTIONINFO PeOperation::EncryptAllSection(pPEInfo pPEInfor)
{

	ENCRYPTIONINFO sEncryption = { 0 };

	unsigned char key1[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//��ʼ��aes����
	CAES aes(key1);

	//��ȡ��������
	DWORD dwSectionCount = GET_FILE_HEADER(pPEInfor->FileBuffer)->NumberOfSections;
	//��ȡ��һ������
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GET_NT_HEADER(pPEInfor->FileBuffer));

	int idx = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".cblt");
		DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".vmp");
		//������Դ ֻ������ ������
		if (dwIsRsrc == 0 || dwIsTls1 == 0|| dwIsTls3 == 0)
		{
			continue;
		}
		else
		{
			sEncryption.sEncryption[idx] = { 0 };

			//��ȡ���ε��׵�ַ�ʹ�С
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)pPEInfor->FileBuffer;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//�޸�����Ϊ��д
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);

			int count = (dwTargetSize - (dwTargetSize % 16)) / 16;
			for (int idx = 0; idx < count; idx++) {
				char* add = (char*)pTargetSection + idx * 16;
				aes.Cipher(add, 16);
			}

			//�޸Ļ�ԭ��������
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//�������ݵ�������Ϣ�ṹ��
			sEncryption.sEncryption[idx].rva = pFirstSection[i].VirtualAddress;
			sEncryption.sEncryption[idx].size = pFirstSection[i].SizeOfRawData;
			idx++;
		}

		sEncryption.indix = idx;
	}
	memcpy(sEncryption.key, key1, 16);

	return sEncryption;
}