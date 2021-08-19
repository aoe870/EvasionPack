#include "stub.h"
#include "AES.h"
#include "lz4.h"

// �ϲ�data/rdata��text��, ��text�ĳɿɶ���д��ִ��
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


typedef struct _STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32;
typedef STRING32 UNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY  InInitializationOrderLinks;	        //����ʼ��˳�򹹳ɵ�ģ�������������д�����Ϊ��
	DWORD   DllBase;				                    //��ģ��ʵ�ʼ��ص����ڴ���ĸ�λ��
	DWORD   EntryPoint;				                    //��ģ�����ڣ���ں���
	DWORD   SizeOfImage;				                //��ģ�����ڴ��еĴ�С
	UNICODE_STRING32    FullDllName;		            //����·����ģ����
	UNICODE_STRING32    BaseDllName;		            //������·����ģ����
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


// ����һ��ȫ�ֱ�������������
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// ���庯��
DefApiFun(GetProcAddress);
DefApiFun(LoadLibraryA);
DefApiFun(VirtualAlloc);
DefApiFun(VirtualProtect);
DefApiFun(VirtualFree);
DefApiFun(CreateWindowExA);
DefApiFun(ExitProcess);
DefApiFun(DefWindowProcA);
DefApiFun(GetStockObject);
DefApiFun(RegisterClassExA);
DefApiFun(ShowWindow);
DefApiFun(UpdateWindow);
DefApiFun(GetMessageA);
DefApiFun(TranslateMessage);
DefApiFun(DispatchMessageA);
DefApiFun(GetWindowTextA);
DefApiFun(PostQuitMessage);
DefApiFun(MessageBoxA);

// ��ȡPEͷ��Ϣ
PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase + GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

// ��ȡ��ǰ���ػ�ַ
__declspec(naked) long getcurmodule()
{
	_asm {
		mov eax, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov eax, dword ptr[ebx + 0x08]
		ret;
	}
}

// ��ȡ����
DWORD MyGetProcAddress(DWORD Module, LPCSTR FunName)
{
	// ��ȡ Dos ͷ�� Nt ͷ
	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
	// ��ȡ������ṹ
	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
	// �ҵ��������Ʊ���ű���ַ��
	auto NameTable = (DWORD*)(ExportTable->AddressOfNames + Module);
	auto FuncTable = (DWORD*)(ExportTable->AddressOfFunctions + Module);
	auto OrdinalTable = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
	// ����������
	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
	{
		// ��ȡ����
		char* Name = (char*)(NameTable[i] + Module);
		if (!strcmp(Name, FunName))
			return FuncTable[OrdinalTable[i]] + Module;
	}
	return -1;
}

// ��ȡ kernel32.dll �Ļ�ַ
//__declspec(naked) long getkernelbase()
HMODULE getKer32Base(void)
{
	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB�е�ģ������ͷ
	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // ����ָ��ģ�������еĸ����ڵ�
	PCHAR pModuleStr = NULL;
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30]   // eax : PEB�ĵ�ַ
		mov eax, [eax + 0x0C]            // eax : ָ��PEB_LDR_DATA�ṹ��ָ��
		mov eax, [eax + 0x1C]            // eax : ģ���ʼ�������ͷָ��InInitializationOrderModuleList
		mov pLdrLinkHead, eax
		pop eax
	}
	pLdrLinkTmp = pLdrLinkHead;
	do {
		if (pLdrLinkTmp) {
			pModuleStr = (PCHAR)(pLdrLinkTmp->BaseDllName.Buffer);
			if (pModuleStr) {
				if ((pModuleStr[0] == 'K' || pModuleStr[0] == 'k') &&
					(pModuleStr[2] == 'E' || pModuleStr[2] == 'e') &&
					(pModuleStr[4] == 'R' || pModuleStr[4] == 'r') &&
					(pModuleStr[6] == 'N' || pModuleStr[6] == 'n') &&
					(pModuleStr[8] == 'E' || pModuleStr[8] == 'e') &&
					(pModuleStr[10] == 'L' || pModuleStr[10] == 'l') &&
					pModuleStr[12] == '3' &&
					pModuleStr[14] == '2' &&
					pModuleStr[16] == '.' &&
					(pModuleStr[18] == 'D' || pModuleStr[18] == 'd') &&
					(pModuleStr[20] == 'L' || pModuleStr[20] == 'l') &&
					(pModuleStr[22] == 'L' || pModuleStr[22] == 'l')
					)
				{
					return (HMODULE)(pLdrLinkTmp->DllBase);
				}
			}
			pLdrLinkTmp = (PLDR_DATA_TABLE_ENTRY)(pLdrLinkTmp->InInitializationOrderLinks.Flink);
			continue;
		}
		break;
	} while (pLdrLinkHead != pLdrLinkTmp);
	return (HMODULE)0;
}

// ��������
long XorDecryptSection()
{
	DWORD OldProtect;
	__asm
	{
		; ��ȡ��ǰ����� PEB ��Ϣ
		mov ebx, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov ebx, dword ptr[ebx + 0x08]
		; �����ػ�ַ�� oep ���
		add ShareData.rva, ebx
	}
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	// ִ�����˵�һ�����ָ��֮�� ShareData.rva ���� va ��
	for (int i = 0; i < ShareData.size; ++i)
		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
}

// ��ת��ԭʼ�� oep
__declspec(naked) long JmpOEP()
{
	__asm
	{
		; ��ȡ��ǰ����� PEB ��Ϣ
		mov ebx, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov ebx, dword ptr[ebx + 0x08]
		; �����ػ�ַ�� oep ���
		add ebx, ShareData.OldOep
		; ��ת��ԭʼ oep ��
		jmp ebx
	}
}

// ��ȡ��Ҫ�õ��ĺ���
void GetAPIAddr()
{
	// ���к������������ȡ
	auto Ker32Base = (DWORD)getKer32Base();
	My_VirtualProtect = (decltype(VirtualProtect)*)MyGetProcAddress(Ker32Base, "VirtualProtect");
	My_GetProcAddress = (decltype(GetProcAddress)*)MyGetProcAddress(Ker32Base, "GetProcAddress");
	My_LoadLibraryA = (decltype(LoadLibraryA)*)MyGetProcAddress(Ker32Base, "LoadLibraryA");
	My_VirtualAlloc = (decltype(VirtualAlloc)*)MyGetProcAddress(Ker32Base, "VirtualAlloc");
	My_VirtualFree = (decltype(VirtualFree)*)MyGetProcAddress(Ker32Base, "VirtualFree");

	DWORD huser = (DWORD)My_LoadLibraryA("user32.dll");
	SetAPI(huser, CreateWindowExA);
	SetAPI(huser, DefWindowProcA);
	SetAPI(huser, RegisterClassExA);
	SetAPI(huser, ShowWindow);
	SetAPI(huser, UpdateWindow);
	SetAPI(huser, GetMessageA);
	SetAPI(huser, TranslateMessage);
	SetAPI(huser, DispatchMessageA);
	SetAPI(huser, GetWindowTextA);
	SetAPI(huser, PostQuitMessage);
	SetAPI(huser, MessageBoxA);

	DWORD hGdi = (DWORD)My_LoadLibraryA("gdi32.dll");
	SetAPI(hGdi, GetStockObject);
}

// 	�޸�ԭʼ�����ض�λ
void FixOldReloc()
{
	// ��ȡ��ǰ���ػ�ַ
	long hModule = getcurmodule();
	DWORD OldProtect;

	// ��ȡ�ض�λ��
	PIMAGE_BASE_RELOCATION RealocTable =
		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);

	if (ShareData.oldRelocRva == 0) {
		return;

	}
	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock )
	{
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, PAGE_READWRITE, &OldProtect);

		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// ����ÿһ���ض�λ��
		for (int i = 0; i < count; i++)
		{
			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
			if (to[i].Type == 3)
			{
				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				DWORD* addr = (DWORD*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
				// ʹ�������ַ��������µ��ض�λ�������
				*addr = *addr - ShareData.oldImageBase + hModule;

			}
		}

		// ��ԭԭ���εĵı�������
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}


	
}

// ��ѹ������
void UncompressSection()
{
	// 1.����ѹ��λ��
	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//2. ����ռ�
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//3. ��ѹ��
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*ѹ���������*/
		pBuff, /*��ѹ����������*/
		ShareData.LaterCompressSize,/*ѹ����Ĵ�С*/
		ShareData.FrontCompressSize/*ѹ��ǰ�Ĵ�С*/);

	//4.�޸�����
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//5.д��ԭʼ����
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//6.�ָ�����
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);


	//7.�ͷſռ�
	//MyVirtualFree(pBuff, 0, MEM_RELEASE);

}

void AESDecryptAllSection()
{
	//��ȡ��ǰ����Ļ�ַ
	DWORD dwBase = getcurmodule();

	CAES aes(ShareData.key1);
	//ѭ��������������
	DWORD old = 0;
	for (int i = 0; i < ShareData.index; i++)
	{
		//�õ��������ε��׵�ַ�ʹ�С
		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
		DWORD dwSectionSize = ShareData.data[i][1];

		//�޸���������
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//���ܴ����
		aes.InvCipher(pSection, dwSectionSize);

		//�������޸Ļ�ȥ
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

// �ָ�����Ŀ¼����Ϣ
void RecoverDataDirTab()
{
	// 1 ��ȡ��ǰ�����ַ
	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	DWORD dwBase = getcurmodule();
	// 2 ��������Ŀ¼��
	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader(dwBase)->DataDirectory);
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		// 3 ��Դ�������޸�
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}
		// 4 �޸�����Ϊ��д
		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
		// 5 �ָ�����Ŀ¼����
		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
		pDataDirectory->Size = ShareData.dwDataDir[i][1];
		// 6 �ָ�ԭ����
		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
		// 7 ����ָ��+1,��������
		pDataDirectory++;
	}
}

// ��̬������
void StaticAntiDebug()
{
	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30] ;//��ȡpeb
		mov al, byte ptr ds : [eax + 0x02] ;//��ȡpeb.beingdugged
		mov BeingDugged, al;
	}
	if (BeingDugged)
	{
		My_MessageBoxA(NULL, "����״̬", "����", MB_OK);
		My_ExitProcess(1);
	}
}


// �Ǵ�����ʼ����
extern "C" __declspec(dllexport) __declspec(naked) void start()
{

	GetAPIAddr();				// ��ȡ������API��ַ
	AESDecryptAllSection();		// ���ܴ����(AES
	UncompressSection();		// ��ѹ������
	StaticAntiDebug();			// ������
	FixOldReloc();				// �޸�ԭʼ�����ض�λ

	if (true) {

		My_MessageBoxA(NULL, "this is pack", "Packer", MB_OK);
		
	}
	else
	{
		JmpOEP();// ��ת��ԭʼ oep
	}
	
}
