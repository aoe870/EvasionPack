#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include "PeOperation.h"

class WinPack
{
public:
	WinPack(std::string path);

	/// <summary>
	/// 保存信息
	/// </summary>
	/// <param name="peinfo"> 待加壳的程序pe信息 </param>
	/// <param name="dll">  </param>
	VOID SavaPeInfo(pPEInfo peinfo, PSHAREDATA data);

	/// <summary>
	/// 保存文件
	/// </summary>
	/// <param name="pPEInfor"> 待加壳的程序pe信息 </param>
	/// <param name="name"> 保存文件为 </param>
	VOID SaveFile(pPEInfo pPEInfor, std::string name = "");

	/// <summary>
	/// 加密代码段
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="Sharedata"></param>
	VOID XorAllSection(pPEInfo pPEInfor, PSHAREDATA Sharedata);
public:

	//
	std::string FileName = "../output/demo_pack.exe";
};

#endif // !Pack_winpack_h
