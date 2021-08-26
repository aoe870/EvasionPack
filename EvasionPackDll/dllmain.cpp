//#include "stub.h"
//#include "AES.h"
//#include "lz4.h"
//
//// 合并data/rdata到text段, 将text改成可读可写可执行
//#pragma comment(linker, "/merge:.data=.text") 
//#pragma comment(linker, "/merge:.rdata=.text")
//#pragma comment(linker, "/section:.text,RWE")

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
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
//	LIST_ENTRY  InInitializationOrderLinks;	        //按初始化顺序构成的模块链表，在驱动中此链表为空
//	DWORD   DllBase;				                    //该模块实际加载到了内存的哪个位置
//	DWORD   EntryPoint;				                    //该模块的入口，入口函数
//	DWORD   SizeOfImage;				                //该模块在内存中的大小
//	UNICODE_STRING32    FullDllName;		            //包含路径的模块名
//	UNICODE_STRING32    BaseDllName;		            //不包含路径的模块名
//}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
//
//typedef struct _UNICODE_STRING {
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//}UNICODE_STRING, * PUNICODE_STRING;
//
//// 导出一个全局变量来共享数据
//extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };
//
//// 定义函数
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
//// 获取当前加载基址
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
//// 获取函数
//AddressSize MyGetProcAddress(AddressSize Module, LPCSTR FunName)
//{
//	// 获取 Dos 头和 Nt 头
//	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
//	auto NtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)Module + DosHeader->e_lfanew);
//	// 获取导出表结构
//	auto ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
//	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Module + ExportRva);
//	// 找到导出名称表、序号表、地址表
//	auto  NameTable = (PULONG)(AddressSize*)(ExportTable->AddressOfNames + (PUCHAR)Module);
//	auto FuncTable = (AddressSize*)(ExportTable->AddressOfFunctions + (PUCHAR)Module);
//	auto OrdinalTable = (USHORT*)(ExportTable->AddressOfNameOrdinals + (PUCHAR)Module);
//	// 遍历找名字
//	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
//	{
//		// 获取名字
//		char* Name = (char*)(NameTable[i] + (PUCHAR)Module);
//
//		// 判断是否查找的函数
//		if (0 == _strnicmp(FunName, Name, strlen(FunName)))
//		{
//			auto lpName = ((PUCHAR)Module + NameTable[i]);
//			//return FuncTable[OrdinalTable[i]] + Module;
//
//			// 获取导出函数地址
//			auto uHint = *(USHORT*)((PUCHAR)Module + ExportTable->AddressOfNameOrdinals + 2 * i);
//			auto ulFuncAddr = *(PULONG)((PUCHAR)Module + ExportTable->AddressOfFunctions + 4 * uHint);
//			return (AddressSize)((PUCHAR)Module + ulFuncAddr);
//		}
//	}
//	return (AddressSize)-1;
//}
//
//// 获取 kernel32.dll 的基址
////__declspec(naked) long getkernelbase()
//HMODULE getKer32Base(void)
//{
//#ifdef _WIN64
//
//	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
//	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x018);  //0x018是LDR相对于PEB偏移   存放着LDR的基地址
//	UNICODE_STRING* FullName;
//	HMODULE hKernel32 = NULL;
//	LIST_ENTRY* pNode = NULL;
//	pNode = (LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //偏移到InInitializationOrderModuleList
//	while (true)
//	{
//		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
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
//	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB中的模块链表头
//	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // 用来指向模块链表中的各个节点
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
//// 解密区段
//long XorDecryptSection()
//{
//	DWORD OldProtect;
//	ShareData.rva += getcurmodule();
//	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
//	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
//	// 执行完了第一个汇编指令之后 ShareData.rva 就是 va 了
//	for (int i = 0; i < ShareData.size; ++i)
//		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
//	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
//	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
//}
//
//// 跳转到原始的 oep
//void JmpOEP()
//{
//	/*__asm
//	{
//		; 获取当前程序的 PEB 信息
//		mov ebx, dword ptr fs : [0x30]
//		; PEB 中偏移为 0x08 保存的是加载基址
//		mov ebx, dword ptr[ebx + 0x08]
//		; 将加载基址和 oep 相加
//		add ebx, ShareData.OldOep
//		; 跳转到原始 oep 处
//		jmp ebx
//	}*/
//	auto Oldbase = getcurmodule() + ShareData.OldOep;
//
//	void (*jump) (); 
//	jump = (void(*)(void))Oldbase;
//	jump();
//}
//
//// 获取想要用到的函数
//void GetAPIAddr()
//{
//	// 所有函数都在这里获取
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
//// 	修复原始程序重定位
//void FixOldReloc()
//{
//	// 获取当前加载基址
//	long hModule = getcurmodule();
//	AddressSize OldProtect;
//
//	// 获取重定位表
//	PIMAGE_BASE_RELOCATION RealocTable =
//		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);
//
//	if (ShareData.oldRelocRva == 0) {
//		return;
//
//	}
//	// 如果 SizeOfBlock 不为空，就说明存在重定位块
//	while (RealocTable->SizeOfBlock )
//	{
//		// 如果重定位的数据在代码段，就需要修改访问属性
//		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
//			0x1000, PAGE_READWRITE, &OldProtect);
//
//		// 获取重定位项数组的首地址和重定位项的数量
//		int count = (RealocTable->SizeOfBlock - 8) / 2;
//		TypeOffset* to = (TypeOffset*)(RealocTable + 1);
//
//		// 遍历每一个重定位项
//		for (int i = 0; i < count; i++)
//		{
//			// 如果 type 的值为 3 我们才需要关注
//			if (to[i].Type == 3)
//			{
//				// 获取到需要重定位的地址所在的位置
//				AddressSize* addr = (AddressSize*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
//				// 使用这个地址，计算出新的重定位后的数据
//				*addr = *addr - ShareData.oldImageBase + hModule;
//
//			}
//		}
//
//		// 还原原区段的的保护属性
//		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
//			0x1000, OldProtect, &OldProtect);
//
//		// 找到下一个重定位块
//		RealocTable = (PIMAGE_BASE_RELOCATION)
//			((DWORD)RealocTable + RealocTable->SizeOfBlock);
//	}
//
//}
//
//// 解压缩区段
//void UncompressSection()
//{
//	// 1.待解压的位置
//	char* pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());
//
//	//2. 申请空间
//	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
//		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//	//3. 解压缩
//	LZ4_uncompress_unknownOutputSize(
//		pSrc,/*压缩后的数据*/
//		pBuff, /*解压出来的数据*/
//		ShareData.LaterCompressSize,/*压缩后的大小*/
//		ShareData.FrontCompressSize/*压缩前的大小*/);
//
//	//4.修改属性
//	DWORD OldProtect;
//	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);
//
//	//5.写入原始数据
//	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);
//
//	//6.恢复属性
//	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);
//
//
//	//7.释放空间
//	//MyVirtualFree(pBuff, 0, MEM_RELEASE);
//
//}
//
///// <summary>
///// 
///// </summary>
//void AESDecryptAllSection()
//{
//	//获取当前程序的基址
//	DWORD dwBase = getcurmodule();
//
//	CAES aes(ShareData.key1);
//	//循环解密所有区段
//	DWORD old = 0;
//	for (int i = 0; i < ShareData.index; i++)
//	{
//		//拿到所有区段的首地址和大小
//		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
//		DWORD dwSectionSize = ShareData.data[i][1];
//
//		//修改区段属性
//		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);
//
//		//解密代码段
//		aes.InvCipher(pSection, dwSectionSize);
//
//		//把属性修改回去
//		My_VirtualProtect(pSection, dwSectionSize, old, &old);
//	}
//}
//
//// 恢复数据目录表信息
//void RecoverDataDirTab()
//{
//	// 1 获取当前程序基址
//	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
//	DWORD dwBase = getcurmodule();
//	// 2 遍历数据目录表
//	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
//	DWORD dwOldAttr = 0;
//	PIMAGE_DATA_DIRECTORY pDataDirectory = (GET_OPTIONAL_HEADER(dwBase)->DataDirectory);
//	for (DWORD i = 0; i < dwNumOfDataDir; i++)
//	{
//		// 3 资源表无需修改
//		if (i == 2)
//		{
//			pDataDirectory++;
//			continue;
//		}
//		// 4 修改属性为可写
//		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
//		// 5 恢复数据目录表项
//		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
//		pDataDirectory->Size = ShareData.dwDataDir[i][1];
//		// 6 恢复原属性
//		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
//		// 7 表项指针+1,继续遍历
//		pDataDirectory++;
//	}
//}
//
//// 静态反调试
//bool StaticAntiDebug()
//{
//	bool BeingDugged = *(DWORD*)(__readfsdword(0x30) + 0x02);;
//	//__asm
//	//{
//	//	mov eax, DWORD ptr fs : [0x30] ;//获取peb
//	//	mov al, byte ptr ds : [eax + 0x02] ;//获取peb.beingdugged
//	//	mov BeingDugged, al;
//	//}
//
//	if (BeingDugged)
//	{
//		My_MessageBoxA(NULL, "调试状态", "警告", MB_OK);
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
//	// 1 获取当前模块基址
//	long Module = getcurmodule();
//	char shellcode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
//	
//	// 3 获取导入表地址=偏移+基址
//	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.ImportRva);
//	// 4 循环遍历导入表(以0结尾
//	while (pImport->Name)
//	{
//		// 5 加载相关dll
//		char* dllName = (char*)(pImport->Name + Module);
//		HMODULE Mod = My_LoadLibraryA(dllName);
//		// 6 获取INT/IAT地址
//		DWORD* pInt = (DWORD*)(pImport->OriginalFirstThunk + Module);
//		DWORD* pIat = (DWORD*)(pImport->FirstThunk + Module);
//		// 7 循环遍历INT(以0结尾
//		while (*pInt)// 其指向THUNK结构体,内部是联合体,不管哪个字段有效,都表示一个地址罢了
//		{
//			// 8 获取API地址
//			IMAGE_IMPORT_BY_NAME* FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
//			LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
//			// 9 申请空间保存"中转站"代码,并将真实地址写入
//			char* pbuff = (char*)My_VirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//			memcpy(pbuff, shellcode, sizeof(shellcode));// 假地址保存"中转站"代码
//			*(DWORD*)&pbuff[5] = (DWORD)Fun;// mov eax,真实地址,jmp eax=jmp 真实地址
//			// 10 向IAT填充假地址(可中转到真地址
//			DWORD old;
//			My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// 可写属性
//			*pIat = (DWORD)pbuff;// 不必管联合体字段,直接赋值到*p即可
//			My_VirtualProtect(pIat, 4, old, &old);// 恢复原属性
//			// 11 下个INT/IAT
//			pInt++;
//			pIat++;
//		}
//
//		// 12 下一个导入表
//		pImport++;
//	}
//
//}
//
//
///// <summary>
///// 沙箱检测
///// </summary>
///// <returns></returns>
//bool  detectionSandbox() {
//
//	//过度
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
//	//内存数量
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
//// 回调函数
//LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
//{
//	// 保存编辑框句柄
//	static HWND Edithwnd = 0;
//
//	switch (msg)
//	{
//	case WM_CREATE:
//	{
//		// 创建窗口
//		HINSTANCE instance = (HINSTANCE)getcurmodule();
//
//		Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 50, 120, 20,
//			hwnd, (HMENU)0x1000, instance, 0);
//		My_CreateWindowExA(0, "button", "确定", WS_VISIBLE | WS_CHILD, 50, 100, 60, 30, hwnd, (HMENU)0x1001, instance, 0);
//		My_CreateWindowExA(0, "button", "取消", WS_VISIBLE | WS_CHILD, 150, 100, 60, 30, hwnd, (HMENU)0x1002, instance, 0);
//		HWND hBit = My_CreateWindowExA(0, "static", "密码", WS_CHILD | WS_VISIBLE, 50, 50, 30, 20, hwnd, (HMENU)1003, instance, NULL);
//
//		break;
//	}
//	case WM_COMMAND:
//	{
//		// 按钮点击事件
//		if (wparam == 0x1001)
//		{
//
//			My_MessageBoxA(NULL, "check", "Packer", MB_OK);
//			char buff[100];
//			// 获取文本
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
//					// 解密代码段(AES
//					AESDecryptAllSection();
//					// 解压缩区段
//					UncompressSection();
//					// 修复原始程序重定位
//					FixOldReloc();
//					//EncodeIAT();
//					JmpOEP();// 跳转到原始 oep
//				}
//
//				//退出窗口
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
//// 显示窗口
//void AlertPassWindow()
//{
//	// 0 创建窗口类
//	WNDCLASSEXA ws = { sizeof(ws) };
//	ws.style = CS_HREDRAW | CS_VREDRAW;
//	ws.hInstance = (HINSTANCE)getcurmodule();
//	ws.lpfnWndProc = MyWndProc;
//	ws.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);
//	ws.lpszClassName = "MyPack";
//
//	//1 .注册窗口类
//	My_RegisterClassExA(&ws);
//
//	//2. 创建窗口
//	HWND hwnd = My_CreateWindowExA(0,
//		"MyPack",
//		"MyPack",
//		WS_OVERLAPPEDWINDOW,
//		100, 100, 300, 200, NULL, NULL,
//		(HINSTANCE)getcurmodule(), NULL);
//
//	//3 . 显示更新
//	My_ShowWindow(hwnd, SW_SHOW);
//	My_UpdateWindow(hwnd);
//
//	//4. 消息循环
//	MSG msg;
//	while (My_GetMessageA(&msg, 0, 0, 0))
//	{
//		//5. 转换消息 分发消息 
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
////反调试
//
//// 壳代码起始函数
//extern "C" __declspec(dllexport) __declspec(naked) void start()
//{
//	// 获取函数的API地址
//	GetAPIAddr();				
//
//	if (AdversarialSandBox()) {
//		if (detectionSandbox() == false && StaticAntiDebug() == false) {
//
//			My_MessageBoxA(NULL, "this is sendBox", "Packer", MB_OK);
//		}
//		else
//		{
//			// 解密代码段(AES
//			AESDecryptAllSection();
//			// 解压缩区段
//			UncompressSection();
//			// 修复原始程序重定位
//			FixOldReloc();
//			//EncodeIAT();
//			JmpOEP();// 跳转到原始 oep
//		}
//	
//	}
//}
