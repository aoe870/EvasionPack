#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include "PeOperation.h"

class WinPack
{
public:
	WinPack(std::string path);

	VOID SavaPeInfo(pPEInfo peinfo, PSHAREDATA dll);

	VOID SaveFile(pPEInfo pPEInfor, std::string name = "");
public:

	std::string FileName = "../output/demo11_pack.exe";
};

#endif // !Pack_winpack_h
