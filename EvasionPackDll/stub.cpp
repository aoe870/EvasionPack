#include "Stub.h"
#include "ReleaseCore.h"
#include <tchar.h>
#include <vector>
EXTERN_C __declspec(dllexport) GLOBAL_PARAM g_stcParam = { (ULONG_PTR)Start };

ReleaseCore Preventdebug;
typedef void(*FUN)();
FUN g_oep;

//初始化信息
ULONG_PTR  InitInformation();
//解密代码
void XorCode();
//正常修复IAT表
void RebuildImportTable();
//解密IAT表
void DecodeIAT();

//反调试函数
void preventdebug();


void Start()
{

	InitInformation();
	RebuildImportTable();

	void (*jump) ();
	jump = (void(*)(void))g_oep;
	jump();

}


//反调试函数
void preventdebug()
{
	//获取被加壳程序的代码基址
	ULONG_PTR uCodeBase = g_stcParam.dwImageBase + g_stcParam.dwOEP;

	//ULONGLONG ji = 0xbfebfbff000a0653;
	////解密绑定的机器码
	//Preventdebug.XorMachineCode(ji, uCodeBase);

	//解密绑定的机器码
	//Preventdebug.XorMachineCode(Preventdebug.GetCPUID(), uCodeBase);

	//if (Preventdebug.IsBebug() ||
	//	Preventdebug.Check_ZwSetInformationObject() ||
	//	Preventdebug.GetProcessIdByName((TCHAR*)_T("vmtoolsd.exe"))//反虚拟机
	//	)
	//{
	//	退出程序
	//	Preventdebug.g_pfnExitProcess(0);
	//}
}


//解密代码
void XorCode()
{
	//获取代码基址
	PBYTE pBase = (PBYTE)(g_stcParam.dwImageBase + g_stcParam.lpStartVA);
	//异或操作
	for (DWORD i = 0; i < g_stcParam.dwCodeSize; i++)
	{
		pBase[i] ^= g_stcParam.byXor;
	}
}

//初始化信息
ULONG_PTR  InitInformation()
{
	//获取IAP的地址
	Preventdebug.InitInformation();

#ifdef _WIN64
	//弹出信息框			
	int nRet = Preventdebug.g_pfnMessageBox(NULL, L"壳程序执行中", L"title", MB_YESNO);
#else
	//弹出信息框			
	int nRet = Preventdebug.g_pfnMessageBox(NULL, L"壳程序执行中", L"title", MB_YESNO);
#endif

	if (nRet == IDYES)
	{
		//修改代码段属性
		ULONG_PTR dwCodeBase = g_stcParam.dwImageBase + (DWORD)g_stcParam.lpStartVA;
		DWORD dwOldProtect = 0;
		Preventdebug.g_pfnVirtualProtect((LPVOID)dwCodeBase, g_stcParam.dwCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		XorCode();//解密代码
		Preventdebug.g_pfnVirtualProtect((LPVOID)dwCodeBase, g_stcParam.dwCodeSize, dwOldProtect, &dwOldProtect);

		g_oep = (FUN)(g_stcParam.dwImageBase + g_stcParam.dwOEP);
		//跳回原始OEP
		return (ULONG_PTR)g_oep;
	}
	//退出程序
	Preventdebug.g_pfnExitProcess(0);
}

//正常修复IAT表
void RebuildImportTable()
{

	//1.获取导入表结构体指针
	PIMAGE_IMPORT_DESCRIPTOR pPEImport =
		(PIMAGE_IMPORT_DESCRIPTOR)(g_stcParam.dwImageBase + g_stcParam.stcPEImportDir.VirtualAddress);

	//2.修改内存属性为可写
	DWORD dwOldProtect = 0;
	Preventdebug.g_pfnVirtualProtect(
		(LPBYTE)(g_stcParam.dwImageBase + g_stcParam.dwIATSectionBase), g_stcParam.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//3.开始修复IAT
	while (pPEImport->Name)
	{
		//获取模块名
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(g_stcParam.dwImageBase + dwModNameRVA);
		HMODULE hMod = Preventdebug.g_pfnLoadLibraryA(pModName);

		//获取IAT信息(有些文件INT是空的，最好用IAT解析，也可两个都解析作对比)
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(g_stcParam.dwImageBase + pPEImport->FirstThunk);

		//获取INT信息(同IAT一样，可将INT看作是IAT的一个备份)
		//PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->OriginalFirstThunk);

		//通过IAT循环获取该模块下的所有函数信息(这里之获取了函数名)
		while (pIAT->u1.AddressOfData)
		{
			//判断是输出函数名还是序号
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				//输出序号
#ifdef _WIN64
				ULONG_PTR dwFunOrdinal = (pIAT->u1.Ordinal) & 0x7FFFFFFFFFFFFFFF;
#else
				DWORD dwFunOrdinal = (pIAT->u1.Ordinal) & 0x7FFFFFFF;
#endif // DEBUG


				ULONG_PTR dwFunAddr = Preventdebug.g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
				*(ULONG_PTR*)pIAT = (ULONG_PTR)dwFunAddr;
			}
			else
			{
				//输出函数名
				ULONG_PTR dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(g_stcParam.dwImageBase + dwFunNameRVA);
				ULONG_PTR dwFunAddr = Preventdebug.g_pfnGetProcAddress(hMod, pstcFunName->Name);
				*(ULONG_PTR*)pIAT = (ULONG_PTR)dwFunAddr;
			}
			pIAT++;
		}
		//遍历下一个模块
		pPEImport++;
	}

	//4.恢复内存属性
	Preventdebug.g_pfnVirtualProtect(
		(LPBYTE)(g_stcParam.dwImageBase + g_stcParam.dwIATSectionBase), g_stcParam.dwIATSectionSize,
		dwOldProtect, &dwOldProtect);
}

//解密IAT表
void DecodeIAT()
{
	//Preventdebug.g_pfnMessageBox(NULL, L"解密IAT表", L"Hello PEDIY", MB_OK);
	//把IAT表的节,设置位可读可写可执行
	DWORD dwOldProtect = 0;
	Preventdebug.g_pfnVirtualProtect(
		(LPBYTE)(g_stcParam.dwImageBase + g_stcParam.dwIATSectionBase), g_stcParam.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//初始化指针信息
	g_stcParam.pMyImport = (PMYIMPORT)(g_stcParam.dwImageBase + g_stcParam.dwIATBaseRVA);
	g_stcParam.pModNameBuf = (CHAR*)g_stcParam.pMyImport + g_stcParam.dwNumOfIATFuns * sizeof(MYIMPORT);
	g_stcParam.pFunNameBuf = (CHAR*)g_stcParam.pModNameBuf + g_stcParam.dwSizeOfModBuf;


	PBYTE pNewAddr = (PBYTE)Preventdebug.g_pfnVirtualAlloc(0, (g_stcParam.dwNumOfIATFuns) * 31, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//解密模块名
	for (DWORD i = 0; i < g_stcParam.dwSizeOfModBuf; i++)
	{
		if (((char*)g_stcParam.pModNameBuf)[i] != 0)
		{
			((char*)g_stcParam.pModNameBuf)[i] ^= g_stcParam.byXor;
		}
	}

	//开始解密
	for (DWORD i = 0; i < g_stcParam.dwNumOfIATFuns; i++)
	{
		HMODULE hMod = NULL;
		//获取模块名称
		char* pModName = (char*)g_stcParam.pModNameBuf + g_stcParam.pMyImport[i].m_dwModNameRVA;
		hMod = Preventdebug.g_pfnGetModuleHandleA(pModName);
		if (hMod == NULL)
		{
			hMod = Preventdebug.g_pfnLoadLibraryA(pModName);
		}

		if (g_stcParam.pMyImport[i].m_bIsOrdinal)
		{
			//*********************************序号导出函数********************************

			ULONG_PTR dwFunOrdinal = g_stcParam.pMyImport[i].m_Ordinal;
			ULONG_PTR dwFunAddr = Preventdebug.g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
			//*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)dwFunAddr;

			//添加了花指令，"MSVCP140.dll"暂时不要处理，会出错，原因还未找到
			if (_stricmp(pModName, "MSVCP140.dll") != 0)
			{
#ifdef _WIN64
				BYTE byByte[]{ 0xEB ,0x02 ,0xE8 ,0x32 ,0x50 ,0x48 ,0xC7 ,0xC0 ,0x66 ,0x66 ,0x88	,0x88 ,0x58,
					0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x35,0x15,0x15,0x15,0x15,0x50,0xc3
				};
				*(ULONG_PTR*)(byByte + 15) = (ULONG_PTR)dwFunAddr ^ 0x15151515;
				memcpy(pNewAddr + sizeof(byByte) * i, byByte, sizeof(byByte));
				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)(pNewAddr + sizeof(byByte) * i);
#else
				BYTE byByte[]{ 0xEB ,0x02 ,0xE8 ,0x32 ,0x50 ,0xB8 ,0x66,
				 0x66 ,0x88 ,0x88 ,0x58 ,0xB8,0x00,0x00,0x00,0x00,0x35,0x15,0x15,0x15,0x15,0x50,0xC3 };
				*(ULONG_PTR*)(byByte + 12) = (ULONG_PTR)dwFunAddr ^ 0x15151515;
				memcpy(pNewAddr + sizeof(byByte) * i, byByte, sizeof(byByte));
				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)(pNewAddr + sizeof(byByte) * i);
#endif // _WIN64				
			}
			else
			{
				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)dwFunAddr;
			}
		}
		else//********************************函数名导出函数*************************************
		{
			//解密IAT函数名
			ULONG_PTR dwFunNameRVA = g_stcParam.pMyImport[i].m_dwFunNameRVA;
			char* pFunName = (char*)g_stcParam.pFunNameBuf + dwFunNameRVA;
			DWORD j = 0;

			while (pFunName[j])
			{
				((char*)pFunName)[j] ^= g_stcParam.byXor;
				j++;
			}

			ULONG_PTR dwFunAddr = Preventdebug.g_pfnGetProcAddress(hMod, pFunName);

			/*
			*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)dwFunAddr;*/

			//添加了花指令，"MSVCP140.dll"暂时不要处理，会出错，原因还未找到
			if (_stricmp(pModName, "MSVCP140.dll") != 0)
			{
#ifdef _WIN64
				BYTE byByte[]{ 0xEB ,0x02 ,0xE8 ,0x32 ,0x50 ,0x48 ,0xC7 ,0xC0 ,0x66 ,0x66 ,0x88	,0x88 ,0x58,
					0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x35,0x68,0x68,0x68,0x68,0x50,0xc3
				};
				*(ULONG_PTR*)(byByte + 15) = (ULONG_PTR)dwFunAddr ^ 0x68686868;
				memcpy(pNewAddr + sizeof(byByte) * i, byByte, sizeof(byByte));

				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)(pNewAddr + sizeof(byByte) * i);

#else
				BYTE byByte[]{ 0xEB ,0x02 ,0xE8 ,0x32 ,0x50 ,0xB8 ,0x66,
				 0x66 ,0x88 ,0x88 ,0x58 ,0xB8,0x00,0x00,0x00,0x00,0x35,0x68,0x68,0x68,0x68,0x50,0xC3 };
				*(ULONG_PTR*)(byByte + 12) = (ULONG_PTR)dwFunAddr ^ 0x68686868;
				memcpy(pNewAddr + sizeof(byByte) * i, byByte, sizeof(byByte));
				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)(pNewAddr + sizeof(byByte) * i);
#endif // _WIN64

			}
			else
			{
				*(ULONG_PTR*)((ULONG_PTR)g_stcParam.pMyImport[i].m_dwIATAddr + g_stcParam.dwImageBase) = (ULONG_PTR)dwFunAddr;
			}

			//抹去IAT函数名
			while (j--)
			{
				pFunName[j] = 0;
			}
		}
	}
	//抹去模块名
	for (DWORD i = 0; i < g_stcParam.dwSizeOfModBuf; i++)
	{
		((char*)g_stcParam.pModNameBuf)[i] = 0;
	}
}