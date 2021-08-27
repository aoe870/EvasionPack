#pragma once
#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include <iostream>
#include <Windows.h>
#include "../EvasionPackDll/stub.h"
#include "PeOperation.h"


class WinPack
{

public:

	WinPack(TCHAR* path);

	//��ʼ����
	void StartProtect(HWND hwndDlg, TCHAR* strPath, BYTE byXor, PROTECTOR	pProctect);

	//�������(��CPU���к�ͬ��������ڽ������)
	void XorMachineCode(ULONGLONG cpuId, PEInfo& peinfo);

	//��ȡCPU���к�(64λ����32λͨ��)
	ULONGLONG GetCPUID();

	//���ܴ����
	DWORD XorCode(BYTE byXOR, PEInfo peinfo);

	//��ȡIAT����Ϣ���ض�λ��Ϣ
	void getinfo(char* cbuff);

	//����IAT��
	void SaveImportTab(char* m_pFileBuf);

	//Ĩȥ�����������Ϣ
	void ClearImportTab(char* m_pFileBuf);

	//�������Ҫ��Ŀ¼��Ϣ
	void ClearDirTable(char* filebuff);

	//�ϲ�Ŀ��PE��Stub.dll
	PBYTE MergeSection(PEInfo peinfo, PEInfo stubpeinfo, PBYTE lpMod, BYTE byXor);

	//�����ļ�
	void SaveFile_pack(TCHAR* strPath, char* NewBuffer, ULONG_PTR m_uTotalSize);

private:
	AllocMemory m_allocMemory;

	PMYIMPORT		m_pMyImport;
	PVOID			m_pModNameBuf;
	PVOID			m_pFunNameBuf;
	ULONG_PTR		m_dwNumOfIATFuns = 0;
	ULONG_PTR		m_dwSizeOfModBuf = 0;
	ULONG_PTR		m_dwSizeOfFunBuf = 0;


	ULONG_PTR					m_IATSectionBase = 0;	//IAT���ڶλ�ַ
	DWORD						m_IATSectionSize = 0;	//IAT���ڶδ�С

	IMAGE_DATA_DIRECTORY		m_PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY		m_PEImportDir;		//�������Ϣ


	ULONG_PTR m_uTotalSize = 0;//��¼�ϲ�����ܴ�С
};
#endif // PACK_WINPACK_H