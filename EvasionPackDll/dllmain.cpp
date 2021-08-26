//#include "stub.h"
//#include "AES.h"
//#include "lz4.h"
//
//// �ϲ�data/rdata��text��, ��text�ĳɿɶ���д��ִ��
//#pragma comment(linker, "/merge:.data=.text") 
//#pragma comment(linker, "/merge:.rdata=.text")
//#pragma comment(linker, "/section:.text,RWE")

#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����
// Windows ͷ�ļ�
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //MessageBoxW(0, 0, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}




//#define GET_DOS_HEADER(x) ((PIMAGE_DOS_HEADER)(x))
//#define GET_NT_HEADER(x) ((PIMAGE_NT_HEADERS)((DWORD)GET_DOS_HEADER(x)->e_lfanew + (DWORD)(x)))
//#define GET_FILE_HEADER(x) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(x)->FileHeader))
//#define GET_OPTIONAL_HEADER(x) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(x)->OptionalHeader))
//#define GET_SECTION_HEADER( x ) ((PIMAGE_SECTION_HEADER)        \
//    ((ULONG_PTR)(GET_NT_HEADER(x)) +                                            \
//     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
//     ((GET_NT_HEADER(x)))->FileHeader.SizeOfOptionalHeader   \
//    ))
//
//#ifdef _WIN64
//#define  AddressSize PVOID64
//#else _WIN32
//#define  AddressSize DWORD
//#endif 
//
//typedef struct _STRING32 {
//	USHORT   Length;
//	USHORT   MaximumLength;
//	ULONG  Buffer;
//} STRING32;
//typedef STRING32 UNICODE_STRING32;
//
//typedef struct _LDR_DATA_TABLE_ENTRY {
//	LIST_ENTRY  InInitializationOrderLinks;	        //����ʼ��˳�򹹳ɵ�ģ�������������д�����Ϊ��
//	DWORD   DllBase;				                    //��ģ��ʵ�ʼ��ص����ڴ���ĸ�λ��
//	DWORD   EntryPoint;				                    //��ģ�����ڣ���ں���
//	DWORD   SizeOfImage;				                //��ģ�����ڴ��еĴ�С
//	UNICODE_STRING32    FullDllName;		            //����·����ģ����
//	UNICODE_STRING32    BaseDllName;		            //������·����ģ����
//}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
//
//typedef struct _UNICODE_STRING {
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//}UNICODE_STRING, * PUNICODE_STRING;
//
//// ����һ��ȫ�ֱ�������������
//extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };
//
//// ���庯��
//DefApiFun(GetProcAddress);
//DefApiFun(LoadLibraryA);
//DefApiFun(VirtualAlloc);
//DefApiFun(VirtualProtect);
//DefApiFun(VirtualFree);
//DefApiFun(CreateWindowExA);
//DefApiFun(ExitProcess);
//DefApiFun(DefWindowProcA);
//DefApiFun(GetStockObject);
//DefApiFun(RegisterClassExA);
//DefApiFun(ShowWindow);
//DefApiFun(UpdateWindow);
//DefApiFun(GetMessageA);
//DefApiFun(TranslateMessage);
//DefApiFun(DispatchMessageA);
//DefApiFun(GetWindowTextA);
//DefApiFun(PostQuitMessage);
//DefApiFun(MessageBoxA);
//DefApiFun(GetSystemInfo);
//DefApiFun(GetTickCount64);
//DefApiFun(GlobalMemoryStatusEx);
//
//DefApiFun(CreateFileW)
//DefApiFun(CloseHandle)
//DefApiFun(GetFileAttributesW)
//DefApiFun(ReadFileEx)
//DefApiFun(WriteFile)
//DefApiFun(DeleteFileW)
//
//// ��ȡ��ǰ���ػ�ַ
//AddressSize getcurmodule()
//{
//#ifdef _WIN64
//
//	return *(AddressSize*)(__readgsqword(0x60) + 0x010);
//
//#else _WIN32
//	return *(AddressSize*)(__readfsdword(0x30) + 0x08);
//#endif 
//}
//
//// ��ȡ����
//AddressSize MyGetProcAddress(AddressSize Module, LPCSTR FunName)
//{
//	// ��ȡ Dos ͷ�� Nt ͷ
//	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
//	auto NtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)Module + DosHeader->e_lfanew);
//	// ��ȡ������ṹ
//	auto ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
//	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Module + ExportRva);
//	// �ҵ��������Ʊ���ű���ַ��
//	auto  NameTable = (PULONG)(AddressSize*)(ExportTable->AddressOfNames + (PUCHAR)Module);
//	auto FuncTable = (AddressSize*)(ExportTable->AddressOfFunctions + (PUCHAR)Module);
//	auto OrdinalTable = (USHORT*)(ExportTable->AddressOfNameOrdinals + (PUCHAR)Module);
//	// ����������
//	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
//	{
//		// ��ȡ����
//		char* Name = (char*)(NameTable[i] + (PUCHAR)Module);
//
//		// �ж��Ƿ���ҵĺ���
//		if (0 == _strnicmp(FunName, Name, strlen(FunName)))
//		{
//			auto lpName = ((PUCHAR)Module + NameTable[i]);
//			//return FuncTable[OrdinalTable[i]] + Module;
//
//			// ��ȡ����������ַ
//			auto uHint = *(USHORT*)((PUCHAR)Module + ExportTable->AddressOfNameOrdinals + 2 * i);
//			auto ulFuncAddr = *(PULONG)((PUCHAR)Module + ExportTable->AddressOfFunctions + 4 * uHint);
//			return (AddressSize)((PUCHAR)Module + ulFuncAddr);
//		}
//	}
//	return (AddressSize)-1;
//}
//
//// ��ȡ kernel32.dll �Ļ�ַ
////__declspec(naked) long getkernelbase()
//HMODULE getKer32Base(void)
//{
//#ifdef _WIN64
//
//	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
//	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x018);  //0x018��LDR�����PEBƫ��   �����LDR�Ļ���ַ
//	UNICODE_STRING* FullName;
//	HMODULE hKernel32 = NULL;
//	LIST_ENTRY* pNode = NULL;
//	pNode = (LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //ƫ�Ƶ�InInitializationOrderModuleList
//	while (true)
//	{
//		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName����InInitialzationOrderModuList��ƫ��
//		if (*(FullName->Buffer + 12) == '\0')
//		{
//			return (HMODULE)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
//			break;
//		}
//		pNode = pNode->Flink;
//	}
//	return 0;
//
//#else _WIN32
//	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB�е�ģ������ͷ
//	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // ����ָ��ģ�������еĸ����ڵ�
//	PCHAR pModuleStr = NULL;
//	pLdrLinkTmp = *(PLDR_DATA_TABLE_ENTRY*)(*(DWORD*)(__readfsdword(0x30) + 0x0C) + 0x1c);;
//	do {
//		if (pLdrLinkTmp) {
//			pModuleStr = (PCHAR)(pLdrLinkTmp->BaseDllName.Buffer);
//			if (pModuleStr) {
//				if ((pModuleStr[0] == 'K' || pModuleStr[0] == 'k') &&
//					(pModuleStr[2] == 'E' || pModuleStr[2] == 'e') &&
//					(pModuleStr[4] == 'R' || pModuleStr[4] == 'r') &&
//					(pModuleStr[6] == 'N' || pModuleStr[6] == 'n') &&
//					(pModuleStr[8] == 'E' || pModuleStr[8] == 'e') &&
//					(pModuleStr[10] == 'L' || pModuleStr[10] == 'l') &&
//					pModuleStr[12] == '3' &&
//					pModuleStr[14] == '2' &&
//					pModuleStr[16] == '.' &&
//					(pModuleStr[18] == 'D' || pModuleStr[18] == 'd') &&
//					(pModuleStr[20] == 'L' || pModuleStr[20] == 'l') &&
//					(pModuleStr[22] == 'L' || pModuleStr[22] == 'l')
//					)
//				{
//					return (HMODULE)(pLdrLinkTmp->DllBase);
//				}
//			}
//			pLdrLinkTmp = (PLDR_DATA_TABLE_ENTRY)(pLdrLinkTmp->InInitializationOrderLinks.Flink);
//			continue;
//		}
//		break;
//	} while (pLdrLinkHead != pLdrLinkTmp);
//	return (HMODULE)0;
//#endif 
//}
//
//// ��������
//long XorDecryptSection()
//{
//	DWORD OldProtect;
//	ShareData.rva += getcurmodule();
//	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
//	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
//	// ִ�����˵�һ�����ָ��֮�� ShareData.rva ���� va ��
//	for (int i = 0; i < ShareData.size; ++i)
//		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
//	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
//	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
//}
//
//// ��ת��ԭʼ�� oep
//void JmpOEP()
//{
//	/*__asm
//	{
//		; ��ȡ��ǰ����� PEB ��Ϣ
//		mov ebx, dword ptr fs : [0x30]
//		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
//		mov ebx, dword ptr[ebx + 0x08]
//		; �����ػ�ַ�� oep ���
//		add ebx, ShareData.OldOep
//		; ��ת��ԭʼ oep ��
//		jmp ebx
//	}*/
//	auto Oldbase = getcurmodule() + ShareData.OldOep;
//
//	void (*jump) (); 
//	jump = (void(*)(void))Oldbase;
//	jump();
//}
//
//// ��ȡ��Ҫ�õ��ĺ���
//void GetAPIAddr()
//{
//	// ���к������������ȡ
//	auto Ker32Base = (DWORD)getKer32Base();
//	My_VirtualProtect = (decltype(VirtualProtect)*)MyGetProcAddress(Ker32Base, "VirtualProtect");
//	My_GetProcAddress = (decltype(GetProcAddress)*)MyGetProcAddress(Ker32Base, "GetProcAddress");
//	My_LoadLibraryA = (decltype(LoadLibraryA)*)MyGetProcAddress(Ker32Base, "LoadLibraryA");
//	My_VirtualAlloc = (decltype(VirtualAlloc)*)MyGetProcAddress(Ker32Base, "VirtualAlloc");
//	My_VirtualFree = (decltype(VirtualFree)*)MyGetProcAddress(Ker32Base, "VirtualFree");
//	My_GetSystemInfo = (decltype(GetSystemInfo)*)MyGetProcAddress(Ker32Base, "GetSystemInfo");
//	My_GetTickCount64 = (decltype(GetTickCount64)*)MyGetProcAddress(Ker32Base, "GetTickCount64");
//	My_GlobalMemoryStatusEx = (decltype(GlobalMemoryStatusEx)*)MyGetProcAddress(Ker32Base, "GlobalMemoryStatusEx");
//	
//	My_CloseHandle = (decltype(CloseHandle)*)MyGetProcAddress(Ker32Base, "CloseHandle");
//	My_GetFileAttributesW = (decltype(GetFileAttributesW)*)MyGetProcAddress(Ker32Base, "GetFileAttributesW");
//	My_ReadFileEx = (decltype(ReadFileEx)*)MyGetProcAddress(Ker32Base, "ReadFileEx");
//	My_WriteFile = (decltype(WriteFile)*)MyGetProcAddress(Ker32Base, "WriteFile");
//	My_DeleteFileW = (decltype(DeleteFile)*)MyGetProcAddress(Ker32Base, "DeleteFileW");
//	My_CreateFileW = (decltype(CreateFileW)*)MyGetProcAddress(Ker32Base, "CreateFileW");
//
//
//	DWORD huser = (DWORD)My_LoadLibraryA("user32.dll");
//	SetAPI(huser, CreateWindowExA);
//	SetAPI(huser, DefWindowProcA);
//	SetAPI(huser, RegisterClassExA);
//	SetAPI(huser, ShowWindow);
//	SetAPI(huser, UpdateWindow);
//	SetAPI(huser, GetMessageA);
//	SetAPI(huser, TranslateMessage);
//	SetAPI(huser, DispatchMessageA);
//	SetAPI(huser, GetWindowTextA);
//	SetAPI(huser, PostQuitMessage);
//	SetAPI(huser, MessageBoxA);
//
//	DWORD hGdi = (DWORD)My_LoadLibraryA("gdi32.dll");
//	SetAPI(hGdi, GetStockObject);
//}
//
//// 	�޸�ԭʼ�����ض�λ
//void FixOldReloc()
//{
//	// ��ȡ��ǰ���ػ�ַ
//	long hModule = getcurmodule();
//	AddressSize OldProtect;
//
//	// ��ȡ�ض�λ��
//	PIMAGE_BASE_RELOCATION RealocTable =
//		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);
//
//	if (ShareData.oldRelocRva == 0) {
//		return;
//
//	}
//	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
//	while (RealocTable->SizeOfBlock )
//	{
//		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
//		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
//			0x1000, PAGE_READWRITE, &OldProtect);
//
//		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
//		int count = (RealocTable->SizeOfBlock - 8) / 2;
//		TypeOffset* to = (TypeOffset*)(RealocTable + 1);
//
//		// ����ÿһ���ض�λ��
//		for (int i = 0; i < count; i++)
//		{
//			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
//			if (to[i].Type == 3)
//			{
//				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
//				AddressSize* addr = (AddressSize*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
//				// ʹ�������ַ��������µ��ض�λ�������
//				*addr = *addr - ShareData.oldImageBase + hModule;
//
//			}
//		}
//
//		// ��ԭԭ���εĵı�������
//		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
//			0x1000, OldProtect, &OldProtect);
//
//		// �ҵ���һ���ض�λ��
//		RealocTable = (PIMAGE_BASE_RELOCATION)
//			((DWORD)RealocTable + RealocTable->SizeOfBlock);
//	}
//
//}
//
//// ��ѹ������
//void UncompressSection()
//{
//	// 1.����ѹ��λ��
//	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());
//
//	//2. ����ռ�
//	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
//		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//	//3. ��ѹ��
//	LZ4_uncompress_unknownOutputSize(
//		pSrc,/*ѹ���������*/
//		pBuff, /*��ѹ����������*/
//		ShareData.LaterCompressSize,/*ѹ����Ĵ�С*/
//		ShareData.FrontCompressSize/*ѹ��ǰ�Ĵ�С*/);
//
//	//4.�޸�����
//	DWORD OldProtect;
//	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);
//
//	//5.д��ԭʼ����
//	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);
//
//	//6.�ָ�����
//	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);
//
//
//	//7.�ͷſռ�
//	//MyVirtualFree(pBuff, 0, MEM_RELEASE);
//
//}
//
///// <summary>
///// 
///// </summary>
//void AESDecryptAllSection()
//{
//	//��ȡ��ǰ����Ļ�ַ
//	DWORD dwBase = getcurmodule();
//
//	CAES aes(ShareData.key1);
//	//ѭ��������������
//	DWORD old = 0;
//	for (int i = 0; i < ShareData.index; i++)
//	{
//		//�õ��������ε��׵�ַ�ʹ�С
//		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
//		DWORD dwSectionSize = ShareData.data[i][1];
//
//		//�޸���������
//		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);
//
//		//���ܴ����
//		aes.InvCipher(pSection, dwSectionSize);
//
//		//�������޸Ļ�ȥ
//		My_VirtualProtect(pSection, dwSectionSize, old, &old);
//	}
//}
//
//// �ָ�����Ŀ¼����Ϣ
//void RecoverDataDirTab()
//{
//	// 1 ��ȡ��ǰ�����ַ
//	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
//	DWORD dwBase = getcurmodule();
//	// 2 ��������Ŀ¼��
//	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
//	DWORD dwOldAttr = 0;
//	PIMAGE_DATA_DIRECTORY pDataDirectory = (GET_OPTIONAL_HEADER(dwBase)->DataDirectory);
//	for (DWORD i = 0; i < dwNumOfDataDir; i++)
//	{
//		// 3 ��Դ�������޸�
//		if (i == 2)
//		{
//			pDataDirectory++;
//			continue;
//		}
//		// 4 �޸�����Ϊ��д
//		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
//		// 5 �ָ�����Ŀ¼����
//		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
//		pDataDirectory->Size = ShareData.dwDataDir[i][1];
//		// 6 �ָ�ԭ����
//		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
//		// 7 ����ָ��+1,��������
//		pDataDirectory++;
//	}
//}
//
//// ��̬������
//bool StaticAntiDebug()
//{
//	bool BeingDugged = *(DWORD*)(__readfsdword(0x30) + 0x02);;
//	//__asm
//	//{
//	//	mov eax, DWORD ptr fs : [0x30] ;//��ȡpeb
//	//	mov al, byte ptr ds : [eax + 0x02] ;//��ȡpeb.beingdugged
//	//	mov BeingDugged, al;
//	//}
//
//	if (BeingDugged)
//	{
//		My_MessageBoxA(NULL, "����״̬", "����", MB_OK);
//		My_ExitProcess(1);
//	}
//
//	return true;
//}
//
///// <summary>
///// 
///// </summary>
//void EncodeIAT()
//{
//	 
//	// 1 ��ȡ��ǰģ���ַ
//	long Module = getcurmodule();
//	char shellcode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
//	
//	// 3 ��ȡ������ַ=ƫ��+��ַ
//	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.ImportRva);
//	// 4 ѭ�����������(��0��β
//	while (pImport->Name)
//	{
//		// 5 �������dll
//		char* dllName = (char*)(pImport->Name + Module);
//		HMODULE Mod = My_LoadLibraryA(dllName);
//		// 6 ��ȡINT/IAT��ַ
//		DWORD* pInt = (DWORD*)(pImport->OriginalFirstThunk + Module);
//		DWORD* pIat = (DWORD*)(pImport->FirstThunk + Module);
//		// 7 ѭ������INT(��0��β
//		while (*pInt)// ��ָ��THUNK�ṹ��,�ڲ���������,�����ĸ��ֶ���Ч,����ʾһ����ַ����
//		{
//			// 8 ��ȡAPI��ַ
//			IMAGE_IMPORT_BY_NAME* FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
//			LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
//			// 9 ����ռ䱣��"��תվ"����,������ʵ��ַд��
//			char* pbuff = (char*)My_VirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//			memcpy(pbuff, shellcode, sizeof(shellcode));// �ٵ�ַ����"��תվ"����
//			*(DWORD*)&pbuff[5] = (DWORD)Fun;// mov eax,��ʵ��ַ,jmp eax=jmp ��ʵ��ַ
//			// 10 ��IAT���ٵ�ַ(����ת�����ַ
//			DWORD old;
//			My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// ��д����
//			*pIat = (DWORD)pbuff;// ���ع��������ֶ�,ֱ�Ӹ�ֵ��*p����
//			My_VirtualProtect(pIat, 4, old, &old);// �ָ�ԭ����
//			// 11 �¸�INT/IAT
//			pInt++;
//			pIat++;
//		}
//
//		// 12 ��һ�������
//		pImport++;
//	}
//
//}
//
//
///// <summary>
///// ɳ����
///// </summary>
///// <returns></returns>
//bool  detectionSandbox() {
//
//	//����
//	SYSTEM_INFO systemInfo;
//	My_GetSystemInfo(&systemInfo);
//	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
//	if (numberOfProcessors < 2) {
//		return false;
//	}
//
//	ULONGLONG uptime = My_GetTickCount64() / 1000;
//	if (uptime < 1200) {
//		return false;
//	}
//
//	//�ڴ�����
//	MEMORYSTATUSEX memoryStatus;
//	memoryStatus.dwLength = sizeof(memoryStatus);
//	My_GlobalMemoryStatusEx(&memoryStatus);
//	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
//	if (RAMMB < 1024) {
//		return false;
//	}
//
//	return true;
//
//}
//
//bool AdversarialSandBox() {
//
//	wchar_t name[] = L"a";
//
//	DWORD dwAttrib = My_GetFileAttributesW(name);
//
//	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
//		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
//		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
//		return false;
//	}
//
//	HANDLE hOpenFile = (HANDLE)My_CreateFileW(name,
//		GENERIC_WRITE,          // open for writing
//		0,                      // do not share
//		NULL,                   // default security
//		CREATE_NEW,             // create new file only
//		FILE_ATTRIBUTE_NORMAL,  // normal file
//		NULL);
//	if (hOpenFile == INVALID_HANDLE_VALUE)
//	{
//		hOpenFile = NULL;
//		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
//		return false;
//	}
//
//	char str[] = "t     erwrwhis is test";
//	DWORD dwBytesWritten = 0;
//	auto bErrorFlag = My_WriteFile(
//		hOpenFile,           // open file handle
//		str,      // start of data to write
//		strlen(str),  // number of bytes to write
//		&dwBytesWritten, // number of bytes that were written
//		NULL);
//
//
//	My_CloseHandle(hOpenFile);
//
//	hOpenFile = My_CreateFileW(name,               // file to open
//		GENERIC_READ,          // open for reading
//		FILE_SHARE_READ,       // share for reading
//		NULL,                  // default security
//		OPEN_EXISTING,         // existing file only
//		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
//		NULL);                 // no attr. template
//
//	if (hOpenFile == INVALID_HANDLE_VALUE)
//	{
//
//		hOpenFile = NULL;
//		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
//		return false;
//	}
//
//	char   ReadBuffer[255] = { 0 };
//	OVERLAPPED ol = { 0 };
//	if (FALSE == My_ReadFileEx(hOpenFile, ReadBuffer, 255 - 1, &ol, NULL))
//	{
//		hOpenFile = NULL;
//		My_MessageBoxA(NULL, "Can not open the file", "Playwav", MB_OK);
//		return false;
//	}
//
//	if (ReadBuffer[3] == 0x20) {
//		My_CloseHandle(hOpenFile);
//		My_DeleteFileW(name);
//		return true;
//	}
//
//
//	My_CloseHandle(hOpenFile);	
//	My_DeleteFileW(name);
//	return false;
//}
//
//
//// �ص�����
//LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
//{
//	// ����༭����
//	static HWND Edithwnd = 0;
//
//	switch (msg)
//	{
//	case WM_CREATE:
//	{
//		// ��������
//		HINSTANCE instance = (HINSTANCE)getcurmodule();
//
//		Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 50, 120, 20,
//			hwnd, (HMENU)0x1000, instance, 0);
//		My_CreateWindowExA(0, "button", "ȷ��", WS_VISIBLE | WS_CHILD, 50, 100, 60, 30, hwnd, (HMENU)0x1001, instance, 0);
//		My_CreateWindowExA(0, "button", "ȡ��", WS_VISIBLE | WS_CHILD, 150, 100, 60, 30, hwnd, (HMENU)0x1002, instance, 0);
//		HWND hBit = My_CreateWindowExA(0, "static", "����", WS_CHILD | WS_VISIBLE, 50, 50, 30, 20, hwnd, (HMENU)1003, instance, NULL);
//
//		break;
//	}
//	case WM_COMMAND:
//	{
//		// ��ť����¼�
//		if (wparam == 0x1001)
//		{
//
//			My_MessageBoxA(NULL, "check", "Packer", MB_OK);
//			char buff[100];
//			// ��ȡ�ı�
//			My_GetWindowTextA(Edithwnd, buff, 100);
//			if (!strcmp(buff, "123"))
//			{
//
//				if (detectionSandbox() == false && StaticAntiDebug() == false) {
//
//					My_MessageBoxA(NULL, "this is sendBox", "Packer", MB_OK);
//
//				}
//				else
//				{
//					// ���ܴ����(AES
//					AESDecryptAllSection();
//					// ��ѹ������
//					UncompressSection();
//					// �޸�ԭʼ�����ض�λ
//					FixOldReloc();
//					//EncodeIAT();
//					JmpOEP();// ��ת��ԭʼ oep
//				}
//
//				//�˳�����
//				My_PostQuitMessage(0);
//				My_ShowWindow(hwnd, SW_HIDE);
//				break;
//			}
//		}
//
//		break;
//	}
//
//	}
//
//	return My_DefWindowProcA(hwnd, msg, wparam, lparam);
//}
//
//// ��ʾ����
//void AlertPassWindow()
//{
//	// 0 ����������
//	WNDCLASSEXA ws = { sizeof(ws) };
//	ws.style = CS_HREDRAW | CS_VREDRAW;
//	ws.hInstance = (HINSTANCE)getcurmodule();
//	ws.lpfnWndProc = MyWndProc;
//	ws.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);
//	ws.lpszClassName = "MyPack";
//
//	//1 .ע�ᴰ����
//	My_RegisterClassExA(&ws);
//
//	//2. ��������
//	HWND hwnd = My_CreateWindowExA(0,
//		"MyPack",
//		"MyPack",
//		WS_OVERLAPPEDWINDOW,
//		100, 100, 300, 200, NULL, NULL,
//		(HINSTANCE)getcurmodule(), NULL);
//
//	//3 . ��ʾ����
//	My_ShowWindow(hwnd, SW_SHOW);
//	My_UpdateWindow(hwnd);
//
//	//4. ��Ϣѭ��
//	MSG msg;
//	while (My_GetMessageA(&msg, 0, 0, 0))
//	{
//		//5. ת����Ϣ �ַ���Ϣ 
//		My_TranslateMessage(&msg);
//		My_DispatchMessageA(&msg);
//	}
//
//}
//
//void testss() {
//	//////////////////////////////////////////////////////////////////////////////////////////////////////
//	wchar_t name[] = L"abas";
//	HANDLE hOpenFile = (HANDLE)My_CreateFileW(name,
//		GENERIC_WRITE,          // open for writing
//		0,                      // do not share
//		NULL,                   // default security
//		CREATE_NEW,             // create new file only
//		FILE_ATTRIBUTE_NORMAL,  // normal file
//		NULL);
//	//////////////////////////////////////////////////////////////////////////////////////////////////////
//	My_CloseHandle(hOpenFile);
//	
//	My_MessageBoxA(NULL, "testss21", "Playwav", MB_OK);
//	My_DeleteFileW(name);
//}
//
////������
//
//// �Ǵ�����ʼ����
//extern "C" __declspec(dllexport) __declspec(naked) void start()
//{
//	// ��ȡ������API��ַ
//	GetAPIAddr();				
//
//	if (AdversarialSandBox()) {
//		if (detectionSandbox() == false && StaticAntiDebug() == false) {
//
//			My_MessageBoxA(NULL, "this is sendBox", "Packer", MB_OK);
//		}
//		else
//		{
//			// ���ܴ����(AES
//			AESDecryptAllSection();
//			// ��ѹ������
//			UncompressSection();
//			// �޸�ԭʼ�����ض�λ
//			FixOldReloc();
//			//EncodeIAT();
//			JmpOEP();// ��ת��ԭʼ oep
//		}
//	
//	}
//}
