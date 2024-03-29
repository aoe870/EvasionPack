#include "WinPack.h"
#include "Common.h"
#include <vector>
#include <time.h>
#include <Psapi.h>


std::vector<std::string> DllNameTable{ "EvasionPackDll.dll" };

BYTE byXor = 0x15;


#ifdef _WIN64
	TCHAR szProxyAddr[100] = L"../output/x64/demo_pack_X64.exe";

	TCHAR strPath[] = L"../output/shell64.exe";
#else
	TCHAR szProxyAddr[100] = L"../output/32/demo_pack.exe";

	TCHAR strPath = L"../output/demo.exe";
#endif

WinPack::WinPack(TCHAR* path)
{

	/*----------------------------------------------------------------------------------*/
	/*	加载被加壳程序，处理IAT表和反调试											*/
	/*----------------------------------------------------------------------------------*/
		//获取目标文件PE信息
	PEInfo peinfo;
	PeOperation pe;
	pe.GetPEInformation_(strPath, &peinfo);

	// 判断是否是PE文件
	if (FALSE == pe.IsPEFile((UCHAR*)peinfo.FileBuffer))
	{
		return;
	};

	//拉伸目标文件
	ULONG_PTR TempBuff = pe.StretchFile(peinfo.FileBuffer, peinfo.SizeofImage);

	PROTECTOR pProctect;
	pProctect.EncryptionIAT = false;
	pProctect.AddReDebug = false;


	//保存IAT表
	SaveImportTab((char*)TempBuff);
	//清理IAT表
	ClearImportTab((char*)TempBuff);

		//PEInfo peinfo_debug;
		////更新peinfo_debug信息
		//pe.GetPEInformation_1((char*)TempBuff, &peinfo_debug);
		////绑定机器码
		//XorMachineCode(GetCPUID(), peinfo_debug);
		////更多反调试方法在stub.dll的PreventDebug类里
	

	//获取IAT表信息和重定位信息
	getinfo((char*)TempBuff);


	//把拉伸的文件还原成磁盘大小
	ULONG_PTR TempBuff_1 = (ULONG_PTR)pe.ImageBuff_To_FileBuff((char*)TempBuff, peinfo.FileSize);

	//更新peinfo信息
	pe.GetPEInformation_1((char*)TempBuff_1, &peinfo, peinfo.FileSize);

	//加密代码段
	DWORD dwVirtualAddr = XorCode(byXor, peinfo);

	//----去掉随机加载基址----
	peinfo.OptionalHeader->DllCharacteristics = 0;

	/*----------------------------------------------------------------------------------*/
	/* 获取Stub文件的PE信息，将必要的信息设置到dll中								*/
	/*----------------------------------------------------------------------------------*/
	HMODULE hModule = LoadLibrary(L"EvasionPackDll.dll");
	if (NULL == hModule) hModule = LoadLibrary(L"EvasionPackDll.dll");

	if (NULL == hModule)
	{
		MessageBoxA(NULL, "Stub.dll加载失败，请检查路径", "提示", MB_OK);
		return;
	}

	//把相关信息保存Stub.dll的g_stcParam全局变量里
	//HMODULE 
	PGLOBAL_PARAM pstcParam = (PGLOBAL_PARAM)GetProcAddress(hModule, "g_stcParam");

	pstcParam->dwImageBase = peinfo.ImageBase;
	pstcParam->dwCodeSize = peinfo.SizeOfCode;
	pstcParam->ulBaseOfCode = peinfo.BaseOfCode;
	pstcParam->dwOEP = peinfo.AddressOfEntryPoint;
	pstcParam->byXor = byXor;
	pstcParam->lpStartVA = (PBYTE)dwVirtualAddr;

	//保存IAT的信息到Stub.dll的g_stcParam全局变量里
	pstcParam->stcPEImportDir = m_PEImportDir;
	pstcParam->stcPERelocDir = m_PERelocDir;
	pstcParam->dwIATSectionBase = m_IATSectionBase;
	pstcParam->dwIATSectionSize = m_IATSectionSize;
	pstcParam->dwNumOfIATFuns = m_dwNumOfIATFuns;
	pstcParam->dwSizeOfModBuf = m_dwSizeOfModBuf;

	pstcParam->dwSizeOfFunBuf = m_dwSizeOfFunBuf;
	pstcParam->pProctect.EncryptionIAT = pProctect.EncryptionIAT;
	pstcParam->pProctect.AddReDebug = pProctect.AddReDebug;

	//添加Stub代码段到被加壳程序中
	//读取Stub代码段
	AllocMemory m_alloc;
	MODULEINFO modinfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	pstcParam->dwIATBaseRVA = peinfo.SizeofImage + modinfo.SizeOfImage;
	PBYTE lpMod = m_alloc.auto_malloc<PBYTE>(modinfo.SizeOfImage);
	memcpy_s(lpMod, modinfo.SizeOfImage, hModule, modinfo.SizeOfImage);
	PEInfo stubpeinfo;
	pe.GetPEInformation_1((char*)lpMod, &stubpeinfo);


	//修复重定位表
	ULONG_PTR TarSizeofImage = pe.AlignSize(peinfo.SizeofImage, peinfo.OptionalHeader->SectionAlignment);
	ULONG_PTR value = stubpeinfo.ImageBase - (peinfo.OptionalHeader->ImageBase + TarSizeofImage);

	if (value != 0)
	{
		pe.PerformBaseRelocation((ULONG_PTR)lpMod, value);
	}

	//修改被加壳程序的OEP
	peinfo.OptionalHeader->AddressOfEntryPoint = TarSizeofImage + (pstcParam->dwStart - (ULONG_PTR)hModule);

	//添加新节存
	pe.addSeciton(peinfo.FileBuffer, stubpeinfo.SizeofImage, (char*)".vmp0");


	PBYTE NewBuffer = MergeSection(peinfo, stubpeinfo, lpMod, byXor);

	//清除不需要的目录信息
	ClearDirTable((char*)NewBuffer);

	//保存文件
	SaveFile_pack(szProxyAddr, (char*)NewBuffer, m_uTotalSize);

	//释放内存
	FreeLibrary(hModule);
	return;
}

void WinPack::StartProtect(HWND hwndDlg, TCHAR* strPath, BYTE byXor, PROTECTOR pProctect)
{
}

void WinPack::XorMachineCode(ULONGLONG cpuId, PEInfo& peinfo)
{
	//获取被加壳程序的OEP
	ULONG_PTR uCodeBase = peinfo.FileBuffer + peinfo.AddressOfEntryPoint;

	//与代码段进行亦或
	*(ULONGLONG*)uCodeBase ^= cpuId;
}

ULONGLONG WinPack::GetCPUID()
{
	return ULONGLONG();
}

DWORD WinPack::XorCode(BYTE byXOR, PEInfo peinfo)
{
	//判断基址在哪一节
	ULONG Entry = peinfo.BaseOfCode;
	PIMAGE_SECTION_HEADER Temp = peinfo.pSectionHeader;

	for (int i = 0; i < peinfo.NumberOfSections; i++)
	{
		if (Entry >= Temp->PointerToRawData && Entry < Temp->PointerToRawData + Temp->SizeOfRawData)
		{
			break;
		}
		++Temp;
	}

	//在内存中找到代码段的相对偏移位置
	PBYTE pBase = (PBYTE)(Temp->PointerToRawData + (ULONGLONG)peinfo.FileBuffer);

	//做异或运算加密
	for (int i = 0; i < peinfo.SizeOfCode; i++)
	{
		pBase[i] ^= byXOR;
	}
	return Temp->VirtualAddress;
}

void WinPack::getinfo(char* m_pFileBuf)
{

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;  
	PIMAGE_NT_HEADERS m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + pDosHeader->e_lfanew);


	//保存重定位目录信息
	m_PERelocDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	//保存IAT信息目录信息
	m_PEImportDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	//获取IAT所在的区段的起始位置和大小
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress &&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//保存该区段的起始地址和大小
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
	

}

void WinPack::SaveImportTab(char* m_pFileBuf)
{
	//0.获取导入表结构体指针
	PeOperation pe; 
	DWORD Virtual = pe.GET_HEADER_DICTIONARY((ULONG_PTR)m_pFileBuf, 1);
	if (Virtual == 0)
	{
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pPEImport = (PIMAGE_IMPORT_DESCRIPTOR)(Virtual + m_pFileBuf);
	//1.第一遍循环确定 m_pModNameBuf 和 m_pFunNameBuf 的大小
	DWORD dwSizeOfModBuf = 0;
	DWORD dwSizeOfFunBuf = 0;
	m_dwNumOfIATFuns = 0;
	while (pPEImport->Name)
	{
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(m_pFileBuf + dwModNameRVA);
		dwSizeOfModBuf += (strlen(pModName) + 1);

		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(m_pFileBuf + pPEImport->FirstThunk);

		while (pIAT->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				m_dwNumOfIATFuns++;
			}
			else
			{
				m_dwNumOfIATFuns++;
				ULONG_PTR dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(m_pFileBuf + dwFunNameRVA);
				dwSizeOfFunBuf += (strlen(pstcFunName->Name) + 1);
			}
			pIAT++;
		}
		pPEImport++;
	}

	//2.第二遍循环保存信息

	//申请内存保存IAT表信息
	m_pModNameBuf = m_allocMemory.auto_malloc<PVOID>(dwSizeOfModBuf);
	m_pFunNameBuf = m_allocMemory.auto_malloc<PVOID>(dwSizeOfFunBuf);
	m_pMyImport = m_allocMemory.auto_malloc<PMYIMPORT>(m_dwNumOfIATFuns * sizeof(MYIMPORT));


	pPEImport = (PIMAGE_IMPORT_DESCRIPTOR)(Virtual + m_pFileBuf);
	ULONG_PTR TempNumOfFuns = 0;
	ULONG_PTR TempModRVA = 0;
	ULONG_PTR TempFunRVA = 0;
	while (pPEImport->Name)
	{
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(m_pFileBuf + dwModNameRVA);
		memcpy_s((PCHAR)m_pModNameBuf + TempModRVA, strlen(pModName) + 1,
			pModName, strlen(pModName) + 1);

		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(m_pFileBuf + pPEImport->FirstThunk);

		while (pIAT->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				//保存以序号出方式的函数信息
				m_pMyImport[TempNumOfFuns].m_dwIATAddr = (ULONG_PTR)pIAT - (ULONG_PTR)m_pFileBuf;
				m_pMyImport[TempNumOfFuns].m_bIsOrdinal = TRUE;
#ifdef _WIN64
				m_pMyImport[TempNumOfFuns].m_Ordinal = pIAT->u1.Ordinal & 0x7FFFFFFFFFFFFFFF;
#else
				m_pMyImport[TempNumOfFuns].m_Ordinal = pIAT->u1.Ordinal & 0x7FFFFFFF;
#endif // DEBUG

				m_pMyImport[TempNumOfFuns].m_dwModNameRVA = TempModRVA;
			}
			else
			{
				//保存名称号出方式的函数信息
				m_pMyImport[TempNumOfFuns].m_dwIATAddr = (ULONG_PTR)pIAT - (ULONG_PTR)m_pFileBuf;

				ULONG_PTR dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(m_pFileBuf + dwFunNameRVA);
				memcpy_s((PCHAR)m_pFunNameBuf + TempFunRVA, strlen(pstcFunName->Name) + 1,
					pstcFunName->Name, strlen(pstcFunName->Name) + 1);

				m_pMyImport[TempNumOfFuns].m_dwFunNameRVA = TempFunRVA;
				m_pMyImport[TempNumOfFuns].m_dwModNameRVA = TempModRVA;
				TempFunRVA += (strlen(pstcFunName->Name) + 1);
			}
			TempNumOfFuns++;
			pIAT++;
		}
		TempModRVA += (strlen(pModName) + 1);
		pPEImport++;
	}

	//逆序排列m_pMyImport
	MYIMPORT stcTemp = { 0 };
	DWORD dwTempNum = m_dwNumOfIATFuns / 2;
	for (DWORD i = 0; i < dwTempNum; i++)
	{
		m_pMyImport[i];
		m_pMyImport[m_dwNumOfIATFuns - i - 1];
		memcpy_s(&stcTemp, sizeof(MYIMPORT), &m_pMyImport[i], sizeof(MYIMPORT));
		memcpy_s(&m_pMyImport[i], sizeof(MYIMPORT), &m_pMyImport[m_dwNumOfIATFuns - i - 1], sizeof(MYIMPORT));
		memcpy_s(&m_pMyImport[m_dwNumOfIATFuns - i - 1], sizeof(MYIMPORT), &stcTemp, sizeof(MYIMPORT));
	}

	//保存信息
	m_dwSizeOfModBuf = dwSizeOfModBuf;
	m_dwSizeOfFunBuf = dwSizeOfFunBuf;
}

void WinPack::ClearImportTab(char* m_pFileBuf)
{
	PeOperation pe;
	DWORD DirData = pe.GET_HEADER_DICTIONARY((ULONG_PTR)m_pFileBuf, 1);
	//获取导入表结构体指针
	PIMAGE_IMPORT_DESCRIPTOR pPEImport =
		(PIMAGE_IMPORT_DESCRIPTOR)(m_pFileBuf + DirData);

	//开始循环抹去IAT(导入表)数据
	//每循环一次抹去一个Dll的所有导入信息
	while (pPEImport->Name)
	{
		//抹去模块名
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(m_pFileBuf + dwModNameRVA);
		memset(pModName, 0, strlen(pModName));

		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(m_pFileBuf + pPEImport->FirstThunk);
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(m_pFileBuf + pPEImport->OriginalFirstThunk);

		//抹去IAT、INT和函数名函数序号
		while (pIAT->u1.AddressOfData)
		{
			//判断是输出函数名还是序号
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				//抹去序号就是将pIAT清空
			}
			else
			{
				//输出函数名
				ULONG_PTR dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(m_pFileBuf + dwFunNameRVA);
				//清除函数名和函数序号
				memset(pstcFunName, 0, strlen(pstcFunName->Name) + sizeof(WORD));
			}
			memset(pINT, 0, sizeof(IMAGE_THUNK_DATA));
			memset(pIAT, 0, sizeof(IMAGE_THUNK_DATA));
			pINT++;
			pIAT++;
		}

		//抹去导入表目录信息
		memset(pPEImport, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

		//遍历下一个模块
		pPEImport++;
	}
}

void WinPack::ClearDirTable(char* filebuff)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)filebuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(filebuff + pDosHeader->e_lfanew);

	//清除不需要的目录表信息
	//只留输出表，重定位表，资源表
	DWORD dwCount = 15;
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (i != IMAGE_DIRECTORY_ENTRY_EXPORT &&
			i != IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			i != IMAGE_DIRECTORY_ENTRY_BASERELOC)
		{
			pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
			pNtHeader->OptionalHeader.DataDirectory[i].Size = 0;
		}
	}
}

PBYTE WinPack::MergeSection(PEInfo peinfo, PEInfo stubpeinfo, PBYTE lpMod, BYTE byXor)
{
	PeOperation pe;
	//1、 计算保存IAT所用的空间大小
	DWORD dwIATSize = 0;
	dwIATSize = m_dwSizeOfModBuf + m_dwSizeOfFunBuf + m_dwNumOfIATFuns * sizeof(MYIMPORT);

	if (dwIATSize % peinfo.SectionAlignment)
	{
		dwIATSize = (dwIATSize / peinfo.SectionAlignment + 1) * peinfo.SectionAlignment;
	}
	if (dwIATSize != 0)
	{
		//添加新节存放IAT表
		pe.addSeciton(peinfo.FileBuffer, dwIATSize, (char*)".vmp1");
	}

	//申请新内存合并目标PE和Stub.dll
	ULONG_PTR TarFileSize = pe.AlignSize(peinfo.FileSize, peinfo.OptionalHeader->FileAlignment);//被加壳程序对齐后的文件大小
	ULONG_PTR TotalSize = stubpeinfo.SizeofImage + TarFileSize + dwIATSize;
	m_uTotalSize = TotalSize;//记录合并后的总大小,保存文件时要用到
	PBYTE NewBuffer = m_allocMemory.auto_malloc<PBYTE>(TotalSize + 10);
	memcpy_s(NewBuffer, TarFileSize, (char*)peinfo.FileBuffer, TarFileSize);
	memcpy_s(NewBuffer + TarFileSize, stubpeinfo.SizeofImage, lpMod, stubpeinfo.SizeofImage);

	//如果选择了加密IAT，则把IAT数据到拷贝 '.vmp1' 节
	//拷贝IAT信息
	if (dwIATSize == 0)
	{
		return NewBuffer;
	}
	ULONG_PTR dwIATBaseRVA = peinfo.FileSize + stubpeinfo.SizeofImage;

	memcpy_s(NewBuffer + dwIATBaseRVA,
		dwIATSize, m_pMyImport, m_dwNumOfIATFuns * sizeof(MYIMPORT));

	//加密模块名
	for (DWORD i = 0; i < m_dwSizeOfModBuf; i++)
	{
		if (((char*)m_pModNameBuf)[i] != 0)
		{
			((char*)m_pModNameBuf)[i] ^= byXor;
		}
	}

	memcpy_s(NewBuffer + dwIATBaseRVA + m_dwNumOfIATFuns * sizeof(MYIMPORT),
		dwIATSize, m_pModNameBuf, m_dwSizeOfModBuf);

	//IAT函数名加密
	for (DWORD i = 0; i < m_dwSizeOfFunBuf; i++)
	{
		if (((char*)m_pFunNameBuf)[i] != 0)
		{
			((char*)m_pFunNameBuf)[i] ^= byXor;
		}
	}

	memcpy_s(NewBuffer + dwIATBaseRVA + m_dwNumOfIATFuns * sizeof(MYIMPORT) + m_dwSizeOfModBuf,
		dwIATSize, m_pFunNameBuf, m_dwSizeOfFunBuf);

	return NewBuffer;
}

void WinPack::SaveFile_pack(TCHAR* strPath, char* NewBuffer, ULONG_PTR m_uTotalSize)
{
	
	// 无论文件是否存在，都要创建新的文件
	HANDLE FileHandle = CreateFile(strPath, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 将目标文件的内容读取到创建的缓冲区中
	DWORD Write = 0;
	WriteFile(FileHandle, (LPVOID)NewBuffer, m_uTotalSize, &Write, NULL);

	// 为了防止句柄泄露应该关闭句柄
	CloseHandle(FileHandle);


//	FileOperation fileopt;
//
//	CString str = strPath;
//	int cutsize = str.RightFindChar(strPath, 0x5c);//0x5c是‘\’这个字符的二进制
//	CString s = str.MidCut(cutsize + 1, _tcslen(strPath) - cutsize - 5);
//
//
//	TCHAR Path_Out[MAX_PATH];
//	_tgetcwd(Path_Out, MAX_PATH);//获取当前程序的路径
//
//	str = Path_Out;
//#ifdef UNICODE
//	str = str + L"\\" + s.GetString() + L"_vmp.exe";
//#else
//	str = str + "\\" + s.GetString() + "_vmp.exe";
//#endif // !UNICODE
//
//
//	bool res = fileopt.SaveFile_((char*)NewBuffer, m_uTotalSize, str.GetString());
//	if (res == 0)
//	{
//		MessageBoxW(NULL, L"文件保存失败!!", L"温馨提示", MB_ICONHAND);
//		return;
//	}
//	TCHAR temp[] = _T("加壳成功！\r\n文件所在路径：\r\n");
//	CString ss = temp;
//	ss += str;
//#ifdef UNICODE
//	MessageBoxW(NULL, ss.GetString(), L"温馨提示", MB_ICONINFORMATION);
//#else
//	MessageBoxA(NULL, ss.GetString(), "温馨提示", MB_ICONINFORMATION);
//#endif // !UNICODE
}
