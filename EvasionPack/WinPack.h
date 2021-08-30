//#pragma once
//#ifndef PACK_WINPACK_H
//#define PACK_WINPACK_H
//
//#include <iostream>
//#include <Windows.h>
//
//#define GET_DOS_HEADER(base) ((PIMAGE_DOS_HEADER)(base))
//#define GET_NT_HEADER(base) ((PIMAGE_NT_HEADERS)((ULONG_PTR)GET_DOS_HEADER(base)->e_lfanew + (ULONG_PTR)(base)))
//#define GET_FILE_HEADER(base) ((PIMAGE_FILE_HEADER)(&GET_NT_HEADER(base)->FileHeader))
//#define GET_OPTIONAL_HEADER(base) ((PIMAGE_OPTIONAL_HEADER)(&GET_NT_HEADER(base)->OptionalHeader))
//#define GET_SECTION_HEADER( base ) ((PIMAGE_SECTION_HEADER)        \
//    ((ULONG_PTR)(GET_NT_HEADER(base)) +                                            \
//     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
//     ((GET_NT_HEADER(base)))->FileHeader.SizeOfOptionalHeader   \
//    ))
//
//
//
//// �ض�λ��ṹ��
//struct TypeOffset
//{
//	WORD Offset : 12;
//	WORD Type : 4;
//};
//
//// �������ݽṹ��
//typedef struct _SHAREDATA
//{
//	long OldOep = 0;// ԭʼ oep
//	long rva = 0;// ���ܵ�rva
//	long size = 0;// ���ܵĴ�С
//	BYTE key = 0;// ���ܵ� key
//	long oldRelocRva = 0;// ԭʼ�ض�λ��λ��
//	long oldImageBase = 0;// ԭʼ���ػ�ַ
//
//	DWORD FrontCompressRva;//0
//	DWORD FrontCompressSize;//1
//	DWORD LaterCompressSize;//2
//
//	unsigned char key1[16] = {};//AES������Կ
//	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
//	int data[20][2];  //���ܵ�����RVA��Size	
//
//	int index2 = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
//	int data2[20][2];  //���ܵ�����RVA��Size	
//
//
//	DWORD dwDataDir[20][3];  //����Ŀ¼���RVA��Size	
//	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���
//
//	long ImportRva;
//
//	DWORD TlsCallbackFuncRva;
//	bool bIsTlsUseful;
//
//} SHAREDATA, * PSHAREDATA;
//
//class WinPack
//{
//
//public:
//	WinPack();
//	WinPack(std::string path, std::string fileName);
//	DWORD Alignment(DWORD n, DWORD align);// �ļ�/�ڴ����
//	PIMAGE_SECTION_HEADER GetSection(DWORD Base, LPCSTR SectionName);// ��ȡ����ͷ��Ϣ
//
//public:
//	void LoadExeFile(LPCSTR FileName);// ��ȡĿ�����
//	void AddSection(LPCSTR SectionName, LPCSTR SrcName);//���������
//	void FixReloc();// �޸����ض�λ
//	void SetRelocTable();// �޸�Ŀ���������Ŀ����ض�λ���λ�õ����ض�λ��.stu_re��
//	void SetOEP();// ��������OEP
//	void CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// ��������������(���߿�����ǰ��
//	void SaveFile(LPCSTR FileName);// ������ļ�
//	bool CompressSection(std::string SectionName);// ѹ������
//	void GetDefaultCodeSection(); //��ȡĬ�ϴ����
//	void XorSection(std::string SectionName);// ����������
//	void EncryptAllSection(); //ȫ�μ���
//	void GetPackDefaultCodeSection();//��ȡ�ǵ�Ĭ�ϴ����
//	bool IsFeFile();
//	void SetClearImport();
//
//private:
//	DWORD FileSize = 0;// �ļ���С,�����ڴ�/�����ļ�ʱ���õ�
//	DWORD FileBase = 0;// �ļ�����ַ; DWORD��Ϊ�˼��㷽��
//	DWORD DllBase = 0;// dll �ļ��ػ�ַ/ģ����
//	DWORD StartOffset = 0;// start �����Ķ���ƫ��,���ڼ�����OEP
//	PSHAREDATA ShareData = nullptr;// ���干������,��Ǵ���dll�ṩ��Ϣ(�Թ������ݵĲ�����Ҫд�ڿ�������֮ǰ)
//	std::string PackDefaultCode = "";
//	std::string DefaultCode = "";			//���ӿǳ���Ĭ�ϴ����
//	std::string PackRelocName = ".stu_re";	//�ǵ��ض�λ���������(�ӿǺ�)
//	std::string PackTestSection = ".pack";	//�ǵ�Ĭ�ϴ��������(�ӿǺ�)
//
//};
//#endif // PACK_WINPACK_H