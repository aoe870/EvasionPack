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

	// 2 ���������
	AddSection(PackTestSection.c_str(), ".text");
	AddSection(PackRelocName.c_str(), ".reloc");

	// 3 ��������OEP
	SetOEP();

	// �޸����ض�λ	
	FixReloc();

	// 7 ѹ������
	char* ptmp = (char*)DefaultCode.c_str();
//	CompressSection(ptmp);


	EncryptAllSection();// ������

	// 9 �������������
	CopySectionData(PackTestSection.c_str(), PackDefaultCode.c_str());
	CopySectionData(PackRelocName.c_str(), ".reloc");
	// 10 ���Ϊ���ļ�
	SaveFile("../output/demo_pack1.exe");
}


DWORD WinPack::Alignment(DWORD n, DWORD align)
{
	return n % align == 0 ? n : (n / align + 1) * align;
}

PIMAGE_SECTION_HEADER WinPack::GetSection(DWORD Base, LPCSTR SectionName)
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

VOID WinPack::LoadExeFile(LPCSTR FileName)
{
	// ����ļ����ڣ��ʹ��ļ����򿪵�Ŀ��ֻ��Ϊ�˶�ȡ���е�����
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
		return;
	}

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	FileSize = GetFileSize(FileHandle, NULL);
	if (FileSize == 0xFFFFFFFF) {
		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
		return;
	}

	FileBase = (DWORD)calloc(FileSize, sizeof(BYTE));

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Read = 0;
	ReadFile(FileHandle, (LPVOID)FileBase, FileSize, &Read, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);

	//�ж��Ƿ���PE�ļ�
	IsFeFile();

	//��ȡ�����
	GetDefaultCodeSection();

	///////////////////////////////////////////

	// �Բ�ִ�� DllMain �ķ�ʽ����ģ�鵽��ǰ���ڴ���
	DllBase = (DWORD)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	GetPackDefaultCodeSection();

	// �� dll �л�ȡ�� start ����������������ҳ��ƫ��(���ػ�ַ + ���λ�ַ + ����ƫ��)
	DWORD Start = (DWORD)GetProcAddress((HMODULE)DllBase, "start");
	StartOffset = Start - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

	// ��ȡ��������Ϣ
	ShareData = (PSHAREDATA)GetProcAddress((HMODULE)DllBase, "ShareData");



}

/// <summary>
/// ����µ�����
/// </summary>
/// <param name="SectionName">��������</param>
/// <param name="SrcName">�ǵ���������</param>
VOID WinPack::AddSection(LPCSTR SectionName, LPCSTR SrcName)
{

	// 1. ��ȡ�����α�����һ��Ԫ�صĵ�ַ
	auto LastSection = &GET_SECTION_HEADER(FileBase)
		[GET_FILE_HEADER(FileBase)->NumberOfSections - 1];

	// 2. ���ļ�ͷ�б������������ + 1
	GET_FILE_HEADER(FileBase)->NumberOfSections += 1;

	// 3. ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  �� dll ���ҵ�������Ҫ����������
	auto SrcSection = GetSection(DllBase, SrcName);

	// 5. ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. �����µ����α��е����ݣ� ����
	memcpy(NewSection->Name, SectionName, 7);

	// 7. �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(FileBase)->SectionAlignment);

	// 8. �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(FileBase)->FileAlignment);

	// 9. ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 11. �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
	GET_OPTIONAL_HEADER(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;
}

VOID WinPack::FixReloc()
{
	DWORD Size = 0, OldProtect = 0;

	// ��ȡ��������ض�λ��
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);

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
		for (int i = 0; i < count; ++i)
		{
			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
			if (to[i].Type == 3)
			{
				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				DWORD* addr = (DWORD*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
				DWORD item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;

				// ʹ�������ַ��������µ��ض�λ�������
				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
				// printf("\t%08x - %08X - %08X\n", addr, *addr, item);
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
		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;

		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);

	}

	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics = 0x8100;

	// �޸�Ŀ������ض�λ���λ�õ����ض�λ��.stu_re��
	SetRelocTable();
}


VOID WinPack::SetRelocTable()
{
	// ��ȡԭʼ������ض�λ�����б���
	ShareData->oldRelocRva =
		GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress;

	// �޸��ض�λ���µ����� ��stu_re��
	GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress
		= GetSection(FileBase, PackRelocName.c_str())->VirtualAddress;

	// �޸��ض�λ��С  Ŀ��.director[5].size = ��.director[5].size;
	GET_NT_HEADER(FileBase)->OptionalHeader.DataDirectory[5].Size =
		GET_NT_HEADER(DllBase)->OptionalHeader.DataDirectory[5].Size;

	// �ó���֧���ض�λ
	GET_NT_HEADER(FileBase)->FileHeader.Characteristics &= 0xFFFFFFFE;
	GET_NT_HEADER(FileBase)->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// ����ԭʼ���ػ�ַ�����޸�ʱʹ��
	ShareData->oldImageBase = GET_NT_HEADER(FileBase)->OptionalHeader.ImageBase;

	return VOID();
}

VOID WinPack::SetOEP()
{
	// �޸�ԭʼ oep ֮ǰ������ oep
	ShareData->OldOep = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;

	// --------------------AddressOfEntryPoint----------------------

	// �µ� rav = start �Ķ���ƫ�� + �����ε� rva
	GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint = StartOffset +
		GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
}

VOID WinPack::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
{
	// ��ȡԴ����������ռ�(dll->ӳ��)�еĻ�ַ
	BYTE* SrcData = (BYTE*)(GetSection(DllBase, SrcName)->VirtualAddress + DllBase);

	// ��ȡĿ������������ռ�(��->����)�еĻ�ַ
	BYTE* DestData = (BYTE*)(GetSection(FileBase, SectionName)->PointerToRawData + FileBase);

	// ֱ�ӽ����ڴ濽��
	memcpy(DestData, SrcData, GetSection(DllBase, SrcName)->SizeOfRawData);
}

VOID WinPack::SaveFile(LPCSTR FileName)
{
	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Write = 0;
	WriteFile(FileHandle, (LPVOID)FileBase, FileSize, &Write, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);
}

bool WinPack::CompressSection(char* SectionName)
{
	// ��ȡ���������Ϣ
	PIMAGE_SECTION_HEADER pSection = GetSection(FileBase, SectionName);
	// ѹ��ǰλ��
	char* pRoffset = (char*)(pSection->PointerToRawData + FileBase);
	// �������ļ��еĴ�С
	long lSize = pSection->SizeOfRawData;

	// 0 ����ѹ��ǰ��Ϣ
	// ѹ�����ݵ�RVA
	ShareData->FrontCompressRva = pSection->VirtualAddress;
	// ѹ��ǰ��СSize
	ShareData->FrontCompressSize = lSize;

	// ---------------------------------��ʼѹ��
	// 1 ��ȡԤ����ѹ������ֽ���:
	int compress_size = LZ4_compressBound(lSize);
	// 2. �����ڴ�ռ�, ���ڱ���ѹ���������
	char* pBuff = new char[compress_size];
	// 3. ��ʼѹ���ļ�����(��������ѹ����Ĵ�С)
	ShareData->LaterCompressSize = LZ4_compress(
		pRoffset,/*ѹ��ǰ������*/
		pBuff, /*ѹ���������*/
		lSize/*�ļ�ԭʼ��С*/);

	// 4.��ѹ��������ݸ���ԭʼ����
	memcpy(pRoffset, pBuff, ShareData->LaterCompressSize);

	// 5.�޸���ǰ�����ļ���С 
	pSection->SizeOfRawData = Alignment(ShareData->LaterCompressSize, 0x200);

	// 6.������������������
	PIMAGE_SECTION_HEADER pFront = pSection;
	PIMAGE_SECTION_HEADER pLater = pSection + 1;
	// û�к�һ�����Σ��Ͳ���Ҫ����
	while (pLater->VirtualAddress)
	{
		// ��ǰ���δ�С
		long DesSize = pFront->SizeOfRawData;
		// �ƶ���������κ���
		char* pDest = (char*)(pFront->PointerToRawData + FileBase + DesSize);

		// �¸����δ�С
		long SrcSize = pLater->SizeOfRawData;
		// ��һ������λ��
		char* pSrc = (char*)(pLater->PointerToRawData + FileBase);

		// ��������
		memcpy(pDest, pSrc, SrcSize);

		// �޸��¸�����λ�� ����FileBase��ӦΪ�������ڴ���
		pLater->PointerToRawData = pFront->PointerToRawData + DesSize;

		// ���������¸�����
		pFront += 1;
		pLater += 1;
	}

	// 7.�����޸��ļ�ʵ�ʴ�С
	// ʵ�ʴ�С = ���һ������λ�� + ������δ�С
	FileSize = pFront->PointerToRawData + pFront->SizeOfRawData;

	// 8.�����޸��ļ���С
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 9.�ͷſռ�
	delete[]pBuff;

	return true;
}


/// <summary>
/// ��ȡĬ�ϴ����
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

//����Ĭ�ϴ����
void WinPack::XorSection(std::string SectionName)
{
	// 1. ��ȡ����Ҫ���ܵ����ε���Ϣ
	auto XorSection = GetSection(FileBase, ".text");

	// 2. �ҵ���Ҫ���ܵ��ֶ������ڴ��е�λ��
	BYTE* data = (BYTE*)(XorSection->PointerToRawData + FileBase);

	// 3. ��д����ʱ��Ҫ�ṩ����Ϣ
	srand((unsigned int)time(0));
	ShareData->key = rand() % 0xff;
	ShareData->rva = XorSection->VirtualAddress;
	ShareData->size = XorSection->SizeOfRawData;

	// 4. ѭ����ʼ���м���
	for (int i = 0; i < ShareData->size; ++i)
	{
		data[i] ^= ShareData->key;
	}
}

/// <summary>
/// ������������
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

	//��ʼ��aes����
	CAES aes(key1);

	//��ȡ��������
	DWORD dwSectionCount = GET_FILE_HEADER(FileBase)->NumberOfSections;
	//��ȡ��һ������
	IMAGE_SECTION_HEADER* pFirstSection = GET_SECTION_HEADER(FileBase);
	//���ڱ�������
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


		//������Դ ֻ������ ������
		if (dwIsRsrc == 0 || dwIsTls1 == 0 || dwIsTls3 == 0)// || pFirstSection[i].PointerToRawData == 0 || pFirstSection[i].SizeOfRawData == 0
		{
			continue;
		}
		else       //��ʼ������������
		{
			//��ȡ���ε��׵�ַ�ʹ�С
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)FileBase;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//�޸�����Ϊ��д
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//����Ŀ������
			aes.Cipher(pTargetSection, dwTargetSize);
			//�޸Ļ�ԭ��������
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//�������ݵ�������Ϣ�ṹ��
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
/// �ж��Ƿ���PE�ļ�
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
