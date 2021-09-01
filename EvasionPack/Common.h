#pragma once
#ifndef PACK_CONMMON_H
#define PACK_CONMMON_H
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "Tooltip.h"
#include "EvasionPack.h"

/// <summary>
/// int转string
/// </summary>
/// <param name="a"></param>
/// <returns></returns>
template<typename T>
static std::string IntToString(T a) {
	std::stringstream st;
	st << a;
	std::string str = st.str();
	return str;
}

/// <summary>
/// 打印日志信息
/// </summary>
/// <param name="Log"></param>
/// <param name="Type"></param>
template<typename T> 
static void PrintLog(T Log, int Type = LOGTYPE_OUTPUT) {

	std::vector<std::string> typeTable{ "[!] ", "[+] " };

	std::cout << typeTable[Type] + IntToString(Log) << std::endl;

}

/// <summary>
/// 字符串分割
/// </summary>
/// <param name="s"></param>
/// <param name="tokens"></param>
/// <param name="delim"></param>
static std::vector<std::string> split(const std::string& s, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

static std::string ByteToString(char* key) {
	char* p = new char[sizeof(key)];
	memcpy(p, key, sizeof(key));
	p[sizeof(key)] = 0;
	return std::string(p);
}

static LPCWSTR StringToLPCWSTR(std::string s) {
	size_t origsize = s.length() + 1;
	const size_t newsize = 100;
	size_t convertedChars = 0;
	wchar_t* wcstring = (wchar_t*)malloc(sizeof(wchar_t) * (s.length() - 1));
	mbstowcs_s(&convertedChars, wcstring, origsize, s.c_str(), _TRUNCATE);

	return wcstring;
}
#endif // PACK_CONMMON_H
