#pragma once

//版本号
#define EvasionVersion "EvasionPack v1.0"

//日志类型
#define LOGTRPE_ERROR  0
#define LOGTYPE_OUTPUT 1

#ifdef _WIN64
#define  ReadFSTemporary(Offset)	__readgsdword(Offset)
#else _WIN32
#define  ReadFSTemporary(Offset)	__readfsdword(Offset)
#endif // DEBUG

#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif
