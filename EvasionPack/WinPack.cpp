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
	/* 加载dll																			*/
	/*----------------------------------------------------------------------------------*/

	PEInfo dllinfo;
	dllinfo.FileBuffer = (POINTER_TYPE)LoadLibraryExA(DllNameTable[0].c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (dllinfo.FileBuffer == 0xFFFFFFFF || dllinfo.FileBuffer == 0xFFFFFFFFFFFFFFFF) {
		return;
	}

	pe.GetPeInfo(&dllinfo);

	// 获取到共享信息
	auto ShareData = (PSHAREDATA)GetProcAddress((HMODULE)dllinfo.FileBuffer, "ShareData");

	SavaPeInfo(&peinfo, ShareData);

	pe.AddSection(&peinfo, &dllinfo);

	pe.SetPeOEP(&peinfo, &dllinfo);

	pe.PerformBaseRelocation(&peinfo, &dllinfo);

	pe.SaveFile(&peinfo);
}

VOID WinPack::SavaPeInfo(pPEInfo peinfo, PSHAREDATA dll)
{
	dll->OldOep = peinfo->AddressOfEntryPoint;
}


