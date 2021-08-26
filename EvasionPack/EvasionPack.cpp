// EvasionPack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "Common.h"
#include <iostream>
#include <map>
#include "WinPack.h"

/// <summary>
/// 解析参数
/// </summary>
/// <param name="argv">参数数组</param>
/// <param name="argc">参数数量</param>
/// <param name="table">存储的容器</param>
void AnalyseParameter(char** argv, int argc, std::map<std::string, std::string> &table) {

    for (int iter = 1; iter < argc; iter += 2) {
        if (iter + 1 >= argc) {
            table.insert(std::pair<std::string, std::string>(argv[iter], ""));
        }
 
        else if (split(argv[iter + 1], '-').size() > 1) {
            table.insert(std::pair<std::string, std::string>(argv[iter], ""));
        }
        else {
            table.insert(std::pair<std::string, std::string>(argv[iter], argv[iter + 1]));
        }
    }

}

/// <summary>
/// 
/// </summary>
/// <param name="table"></param>
void GetUserOperate(std::map<std::string, std::string> table) {
    for (auto iter : table) {

        //帮助信息
        if (iter.first == "-h") {
            PrintLog(Help_Test);
        }
        //加壳
        else if (iter.first == "-f") {

            std::string newFileName = "demo_pack1.exe" ;

            for (auto map : table) {
                if (map.first == "-n") {
                    newFileName = map.second;
                }
            }
            WinPack winPack = std::move(WinPack());
            return;

        }
        
    }
}

int main(int argc, char** argv)
{

    //std::cout << LOGO << std::endl;
 
    WinPack winPack = std::move(WinPack());
    return 0;

    if (sizeof(argc) < 2) {

        PrintLog(EVASION_ERROR_ADDRB, LOGTRPE_ERROR);

    }
    std::map<std::string, std::string> paramTable;
    AnalyseParameter(argv, argc, paramTable);
    GetUserOperate(paramTable);
    
}
