#pragma once
#define CLIENT_NAME "[DIGLETT] "

enum class LOGLVL {
    INFO,
    WARN,
    ERR
};

void OutputRequest(PMD_MODULE_DATA data);
bool CmdHandler(HANDLE hDevice, char* line);
void Logger(LOGLVL LVL, const char* message);
void Logger(InputParser::OP_RESULT result);