#include "WinPack.h"
#include <Windows.h>

std::vector<std::string> DllNameTable{ "EvasionPackDll.dll" };

WinPack::WinPack(std::string path)
{

	PEInfo peinfo;
	PeOperation pe;
	pe.LoadPeFIle(path, &peinfo);
	
	if (FALSE == pe.IsPEFile((UCHAR*)peinfo.FileBuffer)) {
		return;
	}
	
	pe.GetPeInfo(&peinfo);

	/*----------------------------------------------------------------------------------*/
	/* ����dll																			*/
	/*----------------------------------------------------------------------------------*/

	PEInfo dllinfo;
	dllinfo.FileBuffer = (POINTER_TYPE)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	
	
	if (dllinfo.FileBuffer == 0xFFFFFFFF || dllinfo.FileBuffer == 0xFFFFFFFFFFFFFFFF) {
		return;
	}

	pe.GetPeInfo(&dllinfo);

	// ��ȡ��������Ϣ
	auto shareAdd = (PSHAREDATA)GetProcAddress((HMODULE)dllinfo.FileBuffer, "ShareData");

	if (shareAdd == NULL) {
		return;
	}
	PSHAREDATA ShareData;
	ShareData = shareAdd;

	//����PE��Ϣ ��Ϣ���ڿǻ�ԭ����ʱ�õ�
	SavaPeInfo(&peinfo, ShareData);


	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	peinfo.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	
	//����µ�����
	pe.AddSection(&peinfo, &dllinfo);

	//�������
	pe.SetPeOEP(&peinfo, &dllinfo);

	//�޸��ض�λ
	pe.PerformBaseRelocation(&peinfo, &dllinfo);

	//�ɻ����
	pe.XorAllSection(&peinfo, ShareData);

	//��������
	pe.CopySectionData(&peinfo, &dllinfo);

	//�����ļ�
	SaveFile(&peinfo);
}

VOID WinPack::SavaPeInfo(pPEInfo peinfo, PSHAREDATA data)
{
	data->oldOep = peinfo->AddressOfEntryPoint;
	data->oldRelocRva = peinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	data->oldImageBase = peinfo->ImageBase;
	data->oldImportRva = peinfo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

}

VOID WinPack::SaveFile(pPEInfo pPEInfor, std::string name)
{
	if (name != "") {
		FileName = name;
	}
	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
	HANDLE FileHandle = CreateFileA(FileName.c_str(), GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Write = 0;
	auto tmp = WriteFile(FileHandle, (LPVOID)pPEInfor->FileBuffer, pPEInfor->FileSize, &Write, NULL);
	auto error = GetLastError();
	TCHAR szBuf[128];
	LPVOID lpMsgBuf;
	auto test = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);
	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);

}
