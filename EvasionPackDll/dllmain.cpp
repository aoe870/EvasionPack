#include "stub.h"
#include "AES.h"
#include "lz4.h"

// 合并data/rdata到text段, 将text改成可读可写可执行
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
	LIST_ENTRY  InInitializationOrderLinks;	        //按初始化顺序构成的模块链表，在驱动中此链表为空
	DWORD   DllBase;				                    //该模块实际加载到了内存的哪个位置
	DWORD   EntryPoint;				                    //该模块的入口，入口函数
	DWORD   SizeOfImage;				                //该模块在内存中的大小
	UNICODE_STRING32    FullDllName;		            //包含路径的模块名
	UNICODE_STRING32    BaseDllName;		            //不包含路径的模块名
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


// 导出一个全局变量来共享数据
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// 定义函数
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

// 获取PE头信息
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

// 获取当前加载基址
__declspec(naked) long getcurmodule()
{
	_asm {
		mov eax, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov eax, dword ptr[ebx + 0x08]
		ret;
	}
}

// 获取函数
DWORD MyGetProcAddress(DWORD Module, LPCSTR FunName)
{
	// 获取 Dos 头和 Nt 头
	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
	// 获取导出表结构
	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
	// 找到导出名称表、序号表、地址表
	auto NameTable = (DWORD*)(ExportTable->AddressOfNames + Module);
	auto FuncTable = (DWORD*)(ExportTable->AddressOfFunctions + Module);
	auto OrdinalTable = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
	// 遍历找名字
	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
	{
		// 获取名字
		char* Name = (char*)(NameTable[i] + Module);
		if (!strcmp(Name, FunName))
			return FuncTable[OrdinalTable[i]] + Module;
	}
	return -1;
}

// 获取 kernel32.dll 的基址
//__declspec(naked) long getkernelbase()
HMODULE getKer32Base(void)
{
	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB中的模块链表头
	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // 用来指向模块链表中的各个节点
	PCHAR pModuleStr = NULL;
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30]   // eax : PEB的地址
		mov eax, [eax + 0x0C]            // eax : 指向PEB_LDR_DATA结构的指针
		mov eax, [eax + 0x1C]            // eax : 模块初始化链表的头指针InInitializationOrderModuleList
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

// 解密区段
long XorDecryptSection()
{
	DWORD OldProtect;
	__asm
	{
		; 获取当前程序的 PEB 信息
		mov ebx, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov ebx, dword ptr[ebx + 0x08]
		; 将加载基址和 oep 相加
		add ShareData.rva, ebx
	}
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	// 执行完了第一个汇编指令之后 ShareData.rva 就是 va 了
	for (int i = 0; i < ShareData.size; ++i)
		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
}

// 跳转到原始的 oep
__declspec(naked) long JmpOEP()
{
	__asm
	{
		; 获取当前程序的 PEB 信息
		mov ebx, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov ebx, dword ptr[ebx + 0x08]
		; 将加载基址和 oep 相加
		add ebx, ShareData.OldOep
		; 跳转到原始 oep 处
		jmp ebx
	}
}

// 获取想要用到的函数
void GetAPIAddr()
{
	// 所有函数都在这里获取
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

// 	修复原始程序重定位
void FixOldReloc()
{
	// 获取当前加载基址
	long hModule = getcurmodule();
	DWORD OldProtect;

	// 获取重定位表
	PIMAGE_BASE_RELOCATION RealocTable =
		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);

	if (ShareData.oldRelocRva == 0) {
		return;

	}
	// 如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock )
	{
		// 如果重定位的数据在代码段，就需要修改访问属性
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, PAGE_READWRITE, &OldProtect);

		// 获取重定位项数组的首地址和重定位项的数量
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// 遍历每一个重定位项
		for (int i = 0; i < count; i++)
		{
			// 如果 type 的值为 3 我们才需要关注
			if (to[i].Type == 3)
			{
				// 获取到需要重定位的地址所在的位置
				DWORD* addr = (DWORD*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
				// 使用这个地址，计算出新的重定位后的数据
				*addr = *addr - ShareData.oldImageBase + hModule;

			}
		}

		// 还原原区段的的保护属性
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, OldProtect, &OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}


	
}

// 解压缩区段
void UncompressSection()
{
	// 1.待解压的位置
	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//2. 申请空间
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//3. 解压缩
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*压缩后的数据*/
		pBuff, /*解压出来的数据*/
		ShareData.LaterCompressSize,/*压缩后的大小*/
		ShareData.FrontCompressSize/*压缩前的大小*/);

	//4.修改属性
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//5.写入原始数据
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//6.恢复属性
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);


	//7.释放空间
	//MyVirtualFree(pBuff, 0, MEM_RELEASE);

}

void AESDecryptAllSection()
{
	//获取当前程序的基址
	DWORD dwBase = getcurmodule();

	CAES aes(ShareData.key1);
	//循环解密所有区段
	DWORD old = 0;
	for (int i = 0; i < ShareData.index; i++)
	{
		//拿到所有区段的首地址和大小
		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
		DWORD dwSectionSize = ShareData.data[i][1];

		//修改区段属性
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//解密代码段
		aes.InvCipher(pSection, dwSectionSize);

		//把属性修改回去
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

// 恢复数据目录表信息
void RecoverDataDirTab()
{
	// 1 获取当前程序基址
	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	DWORD dwBase = getcurmodule();
	// 2 遍历数据目录表
	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader(dwBase)->DataDirectory);
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		// 3 资源表无需修改
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}
		// 4 修改属性为可写
		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
		// 5 恢复数据目录表项
		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
		pDataDirectory->Size = ShareData.dwDataDir[i][1];
		// 6 恢复原属性
		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
		// 7 表项指针+1,继续遍历
		pDataDirectory++;
	}
}

// 静态反调试
void StaticAntiDebug()
{
	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30] ;//获取peb
		mov al, byte ptr ds : [eax + 0x02] ;//获取peb.beingdugged
		mov BeingDugged, al;
	}
	if (BeingDugged)
	{
		My_MessageBoxA(NULL, "调试状态", "警告", MB_OK);
		My_ExitProcess(1);
	}
}


// 壳代码起始函数
extern "C" __declspec(dllexport) __declspec(naked) void start()
{

	GetAPIAddr();				// 获取函数的API地址
	AESDecryptAllSection();		// 解密代码段(AES
	UncompressSection();		// 解压缩区段
	StaticAntiDebug();			// 反调试
	FixOldReloc();				// 修复原始程序重定位

	if (true) {

		My_MessageBoxA(NULL, "this is pack", "Packer", MB_OK);
		
	}
	else
	{
		JmpOEP();// 跳转到原始 oep
	}
	
}
