#include "ReleaseCore.h"

UCHAR* ReleaseCore::GetKernel32Addr()
{
#ifdef _WIN64

	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x018);  //0x018��LDR�����PEBƫ��   �����LDR�Ļ���ַ
	UNICODE_STRING* FullName;
	HMODULE hKernel32 = NULL;
	LIST_ENTRY* pNode = NULL;
	pNode = (LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //ƫ�Ƶ�InInitializationOrderModuleList
	while (true)
	{
		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName����InInitialzationOrderModuList��ƫ��
		if (*(FullName->Buffer + 12) == '\0')
		{
			return (UCHAR*)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
			break;
		}
		pNode = pNode->Flink;
	}
	return 0;

#else _WIN32
	PLDR_DATA_TABLE_ENTRY pLdrLinkHead = NULL;  // PEB�е�ģ������ͷ
	PLDR_DATA_TABLE_ENTRY pLdrLinkTmp = NULL;   // ����ָ��ģ�������еĸ����ڵ�
	PCHAR pModuleStr = NULL;
	pLdrLinkTmp = *(PLDR_DATA_TABLE_ENTRY*)(*(DWORD*)(__readfsdword(0x30) + 0x0C) + 0x1c);;
	do {
		if (pLdrLinkTmp) {
			pModuleStr = (PCHAR)(pLdrLinkTmp->BaseDllName.Buffer);
			if (pModuleStr) {
				if ((pModuleStr[0] == 'K' || pModuleStr[0] == 'k') &&
					(pModuleStr[2] == 'E' || pModuleStr[2] == 'e') &&
					(pModuleStr[4] == 'R' || pModuleStr[4] == 'r') &&
					(pModuleStr[6] == 'N' || pModuleStr[6] == 'n') &&
					(pModuleStr[8] == 'E' || pModuleStr[8] == 'e') &&
					(pModuleStr[10] == 'L' || pModuleStr[10] == 'l') &&
					pModuleStr[12] == '3' &&
					pModuleStr[14] == '2' &&
					pModuleStr[16] == '.' &&
					(pModuleStr[18] == 'D' || pModuleStr[18] == 'd') &&
					(pModuleStr[20] == 'L' || pModuleStr[20] == 'l') &&
					(pModuleStr[22] == 'L' || pModuleStr[22] == 'l')
					)
				{
					return (UCHAR*)(pLdrLinkTmp->DllBase);
				}
			}
			pLdrLinkTmp = (PLDR_DATA_TABLE_ENTRY)(pLdrLinkTmp->InInitializationOrderLinks.Flink);
			continue;
		}
		break;
	} while (pLdrLinkHead != pLdrLinkTmp);

#endif 

	return 0;
}

UCHAR* ReleaseCore::MyGetProcessAddress()
{
	UCHAR* dwBase = GetKernel32Addr();
	// 1. ��ȡDOSͷ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	// 2. ��ȡNTͷ
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)(dwBase + pDos->e_lfanew);
	// 3. ��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. ��ȡ��������Ϣ�ṹ
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwBase + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	DWORD dwModOffset = pExport->Name;

	// Get Export Address Table
	PDWORD pEAT = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	// Get Export Name Table
	PDWORD pENT = (PDWORD)(dwBase + pExport->AddressOfNames);
	// Get Export Index Table
	PWORD  pEIT = (PWORD)(dwBase + pExport->AddressOfNameOrdinals);

	for (DWORD dwOrdinal = 0; dwOrdinal < dwFunCount; dwOrdinal++)
	{
		if (!pEAT[dwOrdinal]) // Export Address offset
			continue;

		// 1. ��ȡ���
		DWORD dwID = pExport->Base + dwOrdinal;
		// 2. ��ȡ����������ַ
		ULONG_PTR dwFunAddrOffset = pEAT[dwOrdinal];

		for (DWORD dwIndex = 0; dwIndex < dwFunNameCount; dwIndex++)
		{
			// ����ű��в��Һ��������
			if (pEIT[dwIndex] == dwOrdinal)
			{
				// ��������������������Ʊ��е�����
				ULONG_PTR dwNameOffset = pENT[dwIndex];
				char* pFunName = (char*)((ULONG_PTR)dwBase + dwNameOffset);
				if (!strcmp(pFunName, "GetProcAddress"))
				{// ���ݺ������Ʒ��غ�����ַ
					return (dwBase + dwFunAddrOffset);
				}
			}
		}
	}
	return 0;
}

void ReleaseCore::InitInformation()
{
	//��ȡkernel32��ַ	
	UCHAR* dwBase = GetKernel32Addr();

	g_pfnGetProcAddress = (fnGetProcAddress)MyGetProcessAddress();
	//��ȡAPI��ַ
	g_pfnLoadLibraryA = (fnLoadLibraryA)g_pfnGetProcAddress((HMODULE)dwBase, "LoadLibraryA");
	g_pfnGetModuleHandleA = (fnGetModuleHandleA)g_pfnGetProcAddress((HMODULE)dwBase, "GetModuleHandleA");
	g_pfnVirtualProtect = (fnVirtualProtect)g_pfnGetProcAddress((HMODULE)dwBase, "VirtualProtect");
	g_pfnVirtualAlloc = (fnVirtualAlloc)g_pfnGetProcAddress((HMODULE)dwBase, "VirtualAlloc");
	HMODULE hUser32 = (HMODULE)g_pfnLoadLibraryA("user32.dll");
	HMODULE hKernel32 = (HMODULE)g_pfnGetModuleHandleA("kernel32.dll");

	g_pfnExitProcess = (fnExitProcess)g_pfnGetProcAddress(hKernel32, "ExitProcess");

	g_pfnMessageBox = (fnMessageBox)g_pfnGetProcAddress(hUser32, "MessageBoxW");
}

void ReleaseCore::XorMachineCode(ULONGLONG cpuId, ULONG_PTR ulCodeOfBase)
{
	//��ȡ���ӿǳ����OEP
	ULONG_PTR uCodeBase = ulCodeOfBase;

	//�����ν������
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect((LPVOID)ulCodeOfBase, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(ULONGLONG*)uCodeBase ^= cpuId;
	g_pfnVirtualProtect((LPVOID)ulCodeOfBase, 1, dwOldProtect, &dwOldProtect);
}


BOOL ReleaseCore::Check_ZwSetInformationObject()
{
		/*-----------------------------------------------------------------------------------------------------------*/
		/*	��32λ�����У����˰ѹ��ӹҵ�64λ��"ntdll.dll"�ϣ�Ȼ�����������ԣ�������crcУ����߼��ؼ��ֽ������������� */
		/*-----------------------------------------------------------------------------------------------------------*/
	HANDLE v3;
	HANDLE TargetHandle;

	typedef NTSTATUS(__stdcall* NTSETINFORMATIONOBJECT)(HANDLE objhandle, int objinforClass, PVOID objinfo, ULONG Length);
	NTSETINFORMATIONOBJECT pZwSetInformationObject;

	typedef BOOL(__stdcall* SETHANDLEINFORMATION)(_In_ HANDLE hObject, _In_ DWORD dwMask, _In_ DWORD dwFlags);
	SETHANDLEINFORMATION pSetHandleInformation;

	typedef BOOL(__stdcall* DUPLICATEHANDLE)(
		_In_ HANDLE hSourceProcessHandle,
		_In_ HANDLE hSourceHandle,
		_In_ HANDLE hTargetProcessHandle,
		_Outptr_ LPHANDLE lpTargetHandle,
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwOptions
		);
	DUPLICATEHANDLE pDuplicateHandle;

	HMODULE hModule_1 = g_pfnLoadLibraryA("kernel32.dll");
	pSetHandleInformation = (SETHANDLEINFORMATION)g_pfnGetProcAddress(hModule_1, "SetHandleInformation");
	pDuplicateHandle = (DUPLICATEHANDLE)g_pfnGetProcAddress(hModule_1, "DuplicateHandle");

	HMODULE hModule = g_pfnLoadLibraryA("ntdll.dll");
	pZwSetInformationObject = (NTSETINFORMATIONOBJECT)g_pfnGetProcAddress(hModule, "ZwSetInformationObject");

	pDuplicateHandle((HANDLE)-1, (HANDLE)-1, (HANDLE)-1, &TargetHandle, 0, 0, 0);
	pZwSetInformationObject(TargetHandle, 4, &TargetHandle, 2);
	pSetHandleInformation(TargetHandle, 2, 2);
	pDuplicateHandle((HANDLE)-1, TargetHandle, (HANDLE)-1, &v3, 0, 0, 1);
#ifdef _WIN64
	return !v3 || v3 == (HANDLE)0xCCCCCCCCCCCCCCCC;
#endif // _WIN64

	return !v3 || v3 == (HANDLE)0xCCCCCCCC;
}

bool ReleaseCore::GetProcessIdByName(TCHAR* szProcessName)
{
	typedef int(__stdcall* LSTRCMP_)(
#ifdef UNICODE
		_In_ LPCWSTR lpString1, _In_ LPCWSTR lpString2
#else
		_In_ LPCSTR lpString1, _In_ LPCSTR lpString2
#endif // UNICODE
		);
	LSTRCMP_ plstrcmpi;

	typedef HANDLE(__stdcall* CREATETOOLHELP32SNAPSHOT)(DWORD dwFlags, DWORD th32ProcessID);
	CREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot;
	typedef BOOL(__stdcall* PROCESS32FIRST)(HANDLE hSnapshot, LPPROCESSENTRY32or64 lppe);
	PROCESS32FIRST pProcess32First;
	typedef BOOL(__stdcall* PROCESS32NEXT)(HANDLE hSnapshot, LPPROCESSENTRY32or64 lppe);
	PROCESS32NEXT pProcess32Next;

	HMODULE hModule_1 = g_pfnLoadLibraryA("kernel32.dll");
	pCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)g_pfnGetProcAddress(hModule_1, "CreateToolhelp32Snapshot");

#ifdef UINCODE
	plstrcmpi = (LSTRCMP_)g_pfnGetProcAddress(hModule_1, "lstrcmpiW");
	pProcess32First = (PROCESS32FIRST)g_pfnGetProcAddress(hModule_1, "Process32FirstW");
	pProcess32Next = (PROCESS32NEXT)g_pfnGetProcAddress(hModule_1, "Process32NextW");

#else
	plstrcmpi = (LSTRCMP_)g_pfnGetProcAddress(hModule_1, "lstrcmpiA");
	pProcess32First = (PROCESS32FIRST)g_pfnGetProcAddress(hModule_1, "Process32First");
	pProcess32Next = (PROCESS32NEXT)g_pfnGetProcAddress(hModule_1, "Process32Next");
#endif // UINCODE

	HANDLE hSnapProcess = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapProcess == NULL)
	{
		return FALSE;
	}
	PROCESSENTRY32or64 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	BOOL bRet = pProcess32First(hSnapProcess, &pe32);
	while (bRet)
	{
		if (plstrcmpi(pe32.szExeFile, szProcessName) == 0)
		{
			//g_pfnMessageBox(NULL, L"���������", L"Hello PEDIY", MB_OK);
			return TRUE;
		}
		bRet = pProcess32Next(hSnapProcess, &pe32);
	}
	return FALSE;
}
