#pragma once


static char LOGO[] = {
">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \r\n"

"'  ######## ##     ##    ###     ######  ####  #######  ##    ## ########     ###     ######  ##    ## \r\n"
"'  ##       ##     ##   ## ##   ##    ##  ##  ##     ## ###   ## ##     ##   ## ##   ##    ## ##   ##  \r\n"
"'  ##       ##     ##  ##   ##  ##        ##  ##     ## ####  ## ##     ##  ##   ##  ##       ##  ##   \r\n"
"'  ######   ##     ## ##     ##  ######   ##  ##     ## ## ## ## ########  ##     ## ##       #####    \r\n"
"'  ##        ##   ##  #########       ##  ##  ##     ## ##  #### ##        ######### ##       ##  ##   \r\n"
"'  ##         ## ##   ##     ## ##    ##  ##  ##     ## ##   ### ##        ##     ## ##    ## ##   ##  \r\n"
"'  ########    ###    ##     ##  ######  ####  #######  ##    ## ##        ##     ##  ######  ##    ## \r\n"

">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \r\n"
};

static char Help_Test[] = {
	"Use:	EvasionPack [File Name] [Options]							\n"
	"TARGET SPECIFICATION:												\n"
	"	-f <File Name> Add pack for PE file								\n"
	"	-n <File Name> The name of the file after the pack				\n"
	"	-h give this help												\n" };

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#define EVASION_ERROR_ADDRB "Please enter parameters"

#define EVASION_ERROR_INPUT "Please enter the correct parameters" 

#define EVASION_ERROR_OPENFILE_NOFILE "Error, Open File Fail"

#define EVASION_ERROR_GETFILESIZE_FAIL "Error，Get File Size Fail"

#define EVASION_ERROR_FILETYPE_ERROR "错误， 不是exe文件"

#define EVASION_ERROR_FILE_ISCOMPRESSED "文件已被压缩"