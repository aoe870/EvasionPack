#pragma once
#ifndef PACK_CONMMON_H
#define PACK_CONMMON_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "Tooltip.h"
#include "EvasionPack.h"
#include <atlstr.h>

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

static TCHAR* stringToTCHAR(std::string str) {
	TCHAR* param = new TCHAR[str.size() + 1];
	param[str.size()] = 0;
	std::copy(str.begin(), str.end(), param);
	return param;
}

#endif // PACK_CONMMON_H
