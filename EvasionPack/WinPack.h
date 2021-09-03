#ifndef PACK_WINPACK_H
#define PACK_WINPACK_H

#include "PeOperation.h"

class WinPack
{
public:
	WinPack(std::string path);

	/// <summary>
	/// ������Ϣ
	/// </summary>
	/// <param name="peinfo"> ���ӿǵĳ���pe��Ϣ </param>
	/// <param name="dll">  </param>
	VOID SavaPeInfo(pPEInfo peinfo, PSHAREDATA data);

	/// <summary>
	/// �����ļ�
	/// </summary>
	/// <param name="pPEInfor"> ���ӿǵĳ���pe��Ϣ </param>
	/// <param name="name"> �����ļ�Ϊ </param>
	VOID SaveFile(pPEInfo pPEInfor, std::string name = "");

	/// <summary>
	/// ���ܴ����
	/// </summary>
	/// <param name="pPEInfor"></param>
	/// <param name="Sharedata"></param>
	VOID XorAllSection(pPEInfo pPEInfor, PSHAREDATA Sharedata);
public:

	//
	std::string FileName = "../output/demo_pack.exe";
};

#endif // !Pack_winpack_h
