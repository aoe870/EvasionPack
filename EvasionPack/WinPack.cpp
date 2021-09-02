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
	auto ShareData = (PSHAREDATA)GetProcAddress((HMODULE)dllinfo.FileBuffer, "ShareData");

	SavaPeInfo(&peinfo, ShareData);
	
	pe.AddSection(&peinfo, &dllinfo);

	pe.SetPeOEP(&peinfo, &dllinfo);

	pe.PerformBaseRelocation(&peinfo, &dllinfo);

	pe.XorAllSection(&peinfo, ShareData);

	pe.CopySectionData(&peinfo, &dllinfo);

	SaveFile(&peinfo);
}

VOID WinPack::SavaPeInfo(pPEInfo peinfo, PSHAREDATA dll)
{
	dll->OldOep = peinfo->AddressOfEntryPoint;
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

