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
//	// 2 ���������
//	AddSection(PackTestSection.c_str(), ".text");
//
//	// 3 ��������OEP
//	SetOEP();
//
//	// �޸����ض�λ	
//	FixReloc();
//
//	////ѹ������
////	CompressSection(DefaultCode);
//
//	// //������
//	//EncryptAllSection();
//
//	XorSection(".text");
//
//	// 9 �������������
//	CopySectionData(PackTestSection.c_str(), PackDefaultCode.c_str());
//
//	// 10 ���Ϊ���ļ�
//	SaveFile(name.c_str());
//
//	return;
//}
//
///// <summary>
///// �ڴ����
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
///// ��ȡģ����
///// </summary>
///// <param name="Base">ģ���ַ</param>
///// <param name="SectionName">�����
///// </param>
///// <returns></returns>
//PIMAGE_SECTION_HEADER WinPack64::GetSection(POINTER_TYPE Base, LPCSTR SectionName)
//{
//	// 1. ��ȡ�����α�ĵ�һ��
//	auto SectionTable = GET_SECTION_HEADER(Base);
//
//	// 2. ��ȡ�����α��Ԫ�ظ���
//	WORD SectionCount = GET_FILE_HEADER(Base)->NumberOfSections;
//
//	// 3. �������α��Ƚ����ε����ƣ�����������Ϣ�ṹ��ĵ�ַ
//	for (WORD i = 0; i < SectionCount; ++i)
//	{
//		// ����ҵ���ֱ�ӷ���
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
//	// ����ļ����ڣ��ʹ��ļ����򿪵�Ŀ��ֻ��Ϊ�˶�ȡ���е�����
//	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, NULL,
//		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	if (FileHandle == INVALID_HANDLE_VALUE) {
//		PrintLog(EVASION_ERROR_OPENFILE_NOFILE);
//		return;
//	}
//
//	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
//	FileSize = GetFileSize(FileHandle, NULL);
//	if (FileSize == 0xFFFFFFFF) {
//		PrintLog(EVASION_ERROR_GETFILESIZE_FAIL);
//		return;
//	}
//
//	FileBase = (POINTER_TYPE)calloc(FileSize, sizeof(BYTE));
//
//	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
//	DWORD Read = 0;
//	ReadFile(FileHandle, (LPVOID)FileBase, FileSize, &Read, NULL);
//
//	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
//	CloseHandle(FileHandle);
//
//	//�ж��Ƿ���PE�ļ�
//	IsFeFile();
//
//	//��ȡ�����
//	GetDefaultCodeSection();
//
//	///////////////////////////////////////////
//	
//	// �Բ�ִ�� DllMain �ķ�ʽ����ģ�鵽��ǰ���ڴ���
//	DllBase = (POINTER_TYPE)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
//
//	GetPackDefaultCodeSection();
//
//	// �� dll �л�ȡ�� start ����������������ҳ��ƫ��(���ػ�ַ + ���λ�ַ + ����ƫ��)
//	POINTER_TYPE Start = (POINTER_TYPE)GetProcAddress((HMODULE)DllBase, "start");
//	StartOffset = Start - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//
//	// ��ȡ��������Ϣ
//	ShareData = (PSHAREDATAA)GetProcAddress((HMODULE)DllBase, "ShareData");
//
//}
//
///// <summary>
///// ����µ�����
///// </summary>
///// <param name="SectionName">��������</param>
///// <param name="SrcName">�ǵ���������</param>
//VOID WinPack64::AddSection(LPCSTR SectionName, LPCSTR SrcName)
//{
//
//	// 1. ��ȡ�����α�����һ��Ԫ�صĵ�ַ
//	auto LastSection = &GET_SECTION_HEADER(FileBase)
//		[GET_FILE_HEADER(FileBase)->NumberOfSections - 1];
//
//	// 2. ���ļ�ͷ�б������������ + 1
//	GET_FILE_HEADER(FileBase)->NumberOfSections += 1;
//
//	// 3. ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
//	auto NewSection = LastSection + 1;
//	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
//
//	// 4.  �� dll ���ҵ�������Ҫ����������
//	auto SrcSection = GetSection(DllBase, SrcName);
//
//	// 5. ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
//	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));
//
//	// 6. �����µ����α��е����ݣ� ����
//	memcpy(NewSection->Name, SectionName, 7);
//
//	// 7. �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
//	NewSection->VirtualAddress = LastSection->VirtualAddress +
//		Alignment(LastSection->Misc.VirtualSize, GET_OPTIONAL_HEADER(FileBase)->SectionAlignment);
//
//	// 8. �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
//	NewSection->PointerToRawData = LastSection->PointerToRawData +
//		Alignment(LastSection->SizeOfRawData, GET_OPTIONAL_HEADER(FileBase)->FileAlignment);
//
//	// 9. ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
//	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
//	FileBase = (POINTER_TYPE)realloc((VOID*)FileBase, FileSize);
//
//	// 11. �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
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
//	// ��ȡ��������ض�λ��
//	PIMAGE_DATA_DIRECTORY pDataDirectory = GET_OPTIONAL_HEADER(DllBase)->DataDirectory;
//	auto RealocTable = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)DllBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
//
//
//	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
//	while (RealocTable->SizeOfBlock)
//	{
//	
//		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
//		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
//			0x1000, PAGE_READWRITE, &OldProtect);
//		
//		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
//		int count = (RealocTable->SizeOfBlock - 8) / 2;
//		TypeOffsets* to = (TypeOffsets*)(RealocTable + 1);
//		
//		// ����ÿһ���ض�λ��������
//		for (int i = 0; i < count; i++)
//		{
//			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
//			if (to[i].Type == 3)
//			{
//							
//				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
//				POINTER_TYPE* addr = (POINTER_TYPE*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);
//
//				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
//				POINTER_TYPE item = *addr - DllBase - GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//
//
//				// ʹ�������ַ��������µ��ض�λ�������
//				*addr = item + GET_OPTIONAL_HEADER(FileBase)->ImageBase + GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//				
//				
//			}
//		}
//		
//		// ��ԭԭ���εĵı�������
//		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
//			0x1000, OldProtect, &OldProtect);
//
//
//		//-----------------------����VirtualAddress�ֶ�--------------------------------------------
//
//		// �ض�λ��VirtualAddress �ֶν����޸ģ���Ҫ���ض�λ���ɿ�д
//		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
//			0x4, PAGE_READWRITE, &OldProtect);
//
//		// ����VirtualAddress���ӿ��е�text�� Ŀ�����pack��
//		// �޸���ʽ ��VirtualAddress - ��.text.VirtualAddress  + Ŀ�����.pack.VirtualAddress
//		RealocTable->VirtualAddress -= GetSection(DllBase, PackDefaultCode.c_str())->VirtualAddress;
//		RealocTable->VirtualAddress += GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//
//		// ��ԭԭ���εĵı�������
//		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
//			0x1000, OldProtect, &OldProtect);
//
//		// �ҵ���һ���ض�λ��
//		RealocTable = (PIMAGE_BASE_RELOCATION)
//			((POINTER_TYPE)RealocTable + RealocTable->SizeOfBlock);
//
//	}
//
//	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
//	GET_OPTIONAL_HEADER(FileBase)->DllCharacteristics = 0;
//
//}
//
///// <summary>
///// ��������OEP
///// </summary>
//VOID WinPack64::SetOEP()
//{
//	// �޸�ԭʼ oep ֮ǰ������ oep
//	ShareData->OldOep = GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint;
//
//	// --------------------AddressOfEntryPoint----------------------
//
//	// �µ� rav = start �Ķ���ƫ�� + �����ε� rva
//	GET_OPTIONAL_HEADER(FileBase)->AddressOfEntryPoint = StartOffset +
//		GetSection(FileBase, PackTestSection.c_str())->VirtualAddress;
//}
//
///// <summary>
///// �������������
///// </summary>
///// <param name="SectionName"></param>
///// <param name="SrcName"></param>
//VOID WinPack64::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
//{
//	// ��ȡԴ����������ռ�(dll->ӳ��)�еĻ�ַ
//	BYTE* SrcData = (BYTE*)(GetSection(DllBase, SrcName)->VirtualAddress + DllBase);
//
//	// ��ȡĿ������������ռ�(��->����)�еĻ�ַ
//	BYTE* DestData = (BYTE*)(GetSection(FileBase, SectionName)->PointerToRawData + FileBase);
//
//	// ֱ�ӽ����ڴ濽��
//	memcpy(DestData, SrcData, GetSection(DllBase, SrcName)->SizeOfRawData);
//}
//
///// <summary>
///// 
///// </summary>
///// <param name="FileName"></param>
//VOID WinPack64::SaveFile(LPCSTR FileName)
//{
//	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
//	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, NULL,
//		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
//	DWORD Write = 0;
//	WriteFile(FileHandle, (LPVOID)FileBase, FileSize, &Write, NULL);
//
//	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
//	CloseHandle(FileHandle);
//}
//
///// <summary>
///// ��ȡĬ�ϴ����
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
///// ����Ĭ�ϴ����
///// </summary>
///// <param name="SectionName"></param>
//void WinPack64::XorSection(std::string SectionName)
//{
//
//	//��ȡ��һ������
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
//			// 1. ��ȡ����Ҫ���ܵ����ε���Ϣ
//			auto XorSection = GetSection(FileBase, sTemp.c_str());
//
//			if (XorSection->SizeOfRawData == 0) {
//				continue;
//			}
//
//			// 2. �ҵ���Ҫ���ܵ��ֶ������ڴ��е�λ��
//			BYTE* data = (BYTE*)(XorSection->PointerToRawData + FileBase);
//
//			// 3. ��д����ʱ��Ҫ�ṩ����Ϣ
//			srand((unsigned int)time(0));
//			ShareData->key[iter] = rand() % 0xff;
//			ShareData->rva[iter] = XorSection->VirtualAddress;
//			ShareData->size[iter] = XorSection->SizeOfRawData;
//
//			// 4. ѭ����ʼ���м���
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
///// �ж��Ƿ���PE�ļ�
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