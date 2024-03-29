#pragma once
#include <windows.h>

extern "C"
{
	typedef struct _MYIMPORT
	{

		ULONG_PTR	m_dwIATAddr;			//IAT地址
		ULONG_PTR	m_dwModNameRVA;			//模块名偏移
		ULONG_PTR	m_dwFunNameRVA;			//函数名偏移
		BOOL		m_bIsOrdinal;			//是否为序号导出函数
		ULONG_PTR	m_Ordinal;				//序号
	}MYIMPORT, * PMYIMPORT;


	typedef struct _PROTECTOR
	{
		unsigned  EncryptionIAT : 1;		//是否IAT加密		
		unsigned  AddReDebug : 1;			//是否增加反调试
	}PROTECTOR, * pPROTECTOR;


	typedef struct _GLOBAL_PARAM
	{
		ULONG_PTR dwStart;		// Stub中的OEP

		BOOL bShowMessage;		// 是否显示解密信息
		ULONG_PTR dwImageBase;	// 映像基址
		ULONG_PTR ulBaseOfCode;	//代码基址
		ULONG_PTR dwOEP;		// 程序入口点
		PBYTE lpStartVA;		// 起始虚拟地址（被异或加密区）
		DWORD dwCodeSize;		// 被加密大小
		BYTE byXor;				// 加密异或的值

		IMAGE_DATA_DIRECTORY	stcPERelocDir;		//重定位表信息
		IMAGE_DATA_DIRECTORY	stcPEImportDir;		//导入表信息

		ULONG_PTR					dwIATSectionBase;	//IAT所在段基址
		DWORD					dwIATSectionSize;	//IAT所在段大小

		//解密IAT所用到的的变量
		PMYIMPORT				pMyImport;
		PVOID					pModNameBuf;
		PVOID					pFunNameBuf;
		ULONG_PTR					dwNumOfIATFuns;
		ULONG_PTR					dwSizeOfModBuf;
		ULONG_PTR					dwSizeOfFunBuf;
		ULONG_PTR					dwIATBaseRVA;

		PROTECTOR	pProctect;
	}GLOBAL_PARAM, * PGLOBAL_PARAM;

	void Start();
}
