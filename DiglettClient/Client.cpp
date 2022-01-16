#include <Windows.h>
#include <algorithm>
#include <iostream>

#include "../DiglettDriver/Common.h"
#include "InputParser.h"
#include "Client.h"

int main(int argc, char** argv) {
	std::cout << "Opening handle to Psched device object...\n\n";
	// open handle to device
	HANDLE hDevice = CreateFile(L"\\\\.\\NUL", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		Logger(LOGLVL::ERR, "Failed to open handle...");
		std::cout << "GetLastError():  " << std::hex << GetLastError() << std::endl;
		system("pause");
		return 1;
	}
	
	bool loop = true;
	//std::string line;
	char line[MAX_LINE_LEN];

	while (loop) {
		std::cout << "DIGLETT> ";
		std::cin.clear();
		std::cin.getline(line, MAX_LINE_LEN);
		
		loop = CmdHandler(hDevice, line);
	}
	
	CloseHandle(hDevice);
	Logger(LOGLVL::INFO, "Handle to driver closed.");
	system("pause");
	return 0;
}

void OutputRequest(PMD_MODULE_DATA data)
{
	std::cout << "\nArguments Sent: " << std::endl;
	std::cout << "\tisAddr: " << data->isAddr << std::endl;
	std::cout << "\tAddress: 0x" << std::hex << data->address << std::endl;
	std::cout << "\tSize: 0x" << std::hex << data->size << std::endl;
	std::cout << "\tmoduleName: " << data->moduleName << std::endl;
}

void OutputRequest(PECHO_DATA echoData)
{
	std::cout << "\nArguments Sent: " << std::endl;
	std::cout << "\tMessage: " << echoData->strEcho << std::endl;
}

bool CmdHandler(HANDLE hDevice, char* line) {
	MD_MODULE_DATA data = {};
	ECHO_DATA echoData = {};
	DWORD returned = 0;
	BOOL success = false;
	InputParser input(line);
	InputParser::OP_RESULT parserResult;

	bool dumpCmd = input.CheckCmd("dump");
	bool helpCmd = input.CheckCmd("help");
	bool echoCmd = input.CheckCmd("echo");
	bool exitCmd = input.CheckCmd("exit");
	bool fastIoCmd = input.CheckCmd("fastio");

	bool modFlag = input.CmdOptionExists("-m");
	bool addrFlag = input.CmdOptionExists("-a");
	bool sizeFlag = input.CmdOptionExists("-l");

	if (helpCmd) {
		std::cout << "\t\t" << "dump " << " " << "[-a <address> -l <length>] | [-m <module_name>]" << std::endl;
		std::cout << "\t\t" << "echo " << " " << "[-m <message>]" << std::endl;
		std::cout << "\t\t" << "exit " << std::endl;
		return PROMPT;
	}
	else if (dumpCmd)
	{
		// dump for address and size
		if (addrFlag && sizeFlag && !modFlag) {
			std::string address = input.GetCmdOption("-a");
			std::string size = input.GetCmdOption("-l");
			parserResult = InputParser::IsAddressValid(address);
			if (!parserResult) {
				// make space for the null char
				size_t length = address.length() + 1 - 2;
				char* pAddr = new char[length];
				strcpy_s(pAddr, length, address.c_str() + 2);
				UINT64 baseAddr = input.ConvertToU64(pAddr, length);
				parserResult = input.IsLengthValid(baseAddr ,size);
				if (!parserResult)
				{
					length = size.length() + 1 - 2;
					char* pAddr2 = new char[length];
					strcpy_s(pAddr2, length, size.c_str() + 2);
					UINT64 len = input.ConvertToU64(pAddr2, length);
					data.isAddr = true;
					data.address = baseAddr;
					data.size = len;
					Logger(LOGLVL::INFO, "Sending dump request with:");
					OutputRequest(&data);
					//success = DeviceIoControl(hDevice, IOCTL_DUMP_KERNEL_MODULE, &data, sizeof(data), nullptr, 0, &returned, nullptr);
					success = true;
					if (success)
						Logger(LOGLVL::INFO, "Dump request succeeded.\n");
					else
						Logger(LOGLVL::ERR, "Dump request failed!\n");
					return PROMPT;
				} else {
					Logger(parserResult);
					return PROMPT;
				}
			} else {
				Logger(parserResult);
				return PROMPT;
			}
		}
		// dump for module name
		else if (modFlag && !addrFlag && !sizeFlag)
		{
			std::string modName = input.GetCmdOption("-m");
			strcpy_s(data.moduleName, MAX_NAME_LENGTH ,modName.c_str());
			OutputRequest(&data);
			success = DeviceIoControl(hDevice, IOCTL_ECHO_REQUEST, &data, sizeof(data), nullptr, 0, &returned, nullptr);
			success = true;
			if (success)
				Logger(LOGLVL::INFO, "Dump request succeeded.\n");
			else
				Logger(LOGLVL::ERR, "Dump request failed!\n");
			return PROMPT;
		}
		else {
			Logger(LOGLVL::INFO, "Usage: dump [-a <address> -l <length>] | [-m <module_name>]");
			return PROMPT;
		}
	}
	else if (echoCmd && modFlag)
	{
		std::string message = input.GetCmdOption("-m");
		strcpy_s(echoData.strEcho, MAX_NAME_LENGTH, message.c_str());
		OutputRequest(&echoData);
		success = DeviceIoControl(hDevice, IOCTL_ECHO_REQUEST, &echoData, sizeof(echoData), nullptr, 0, &returned, nullptr);
		std::cout << "GetLastError(): 0x" << std::hex << GetLastError() << std::endl;
		if (success)
			Logger(LOGLVL::INFO, "Dump request succeeded.\n");
		else
			Logger(LOGLVL::ERR, "Dump request failed!\n");
		return PROMPT;
	}
	else if (fastIoCmd)
	{
		Logger(LOGLVL::INFO, "Attempting fastio!\n");
		success = DeviceIoControl(hDevice, IOCTL_ECHO_REQUEST, nullptr, 0, nullptr, 0, nullptr, nullptr);
		std::cout << "GetLastError(): 0x" << std::hex << GetLastError() << std::endl;
		return PROMPT;
	}
	else if (exitCmd)
	{
		return EXIT;
	}
	else {
		Logger(LOGLVL::WARN, "Unrecognized command, use help for commands.");
		return PROMPT;
	}
	
}

void Logger(LOGLVL LogLvl, const char* message) {
	switch (LogLvl)
	{
	case LOGLVL::INFO:
		std::cout << "\n\n" << CLIENT_NAME << " [INFO] " << message << std::endl << std::endl;
		break;
	case LOGLVL::WARN:
		std::cout << "\n\n" << CLIENT_NAME << " [WARN] " << message << std::endl << std::endl;
		break;
	case LOGLVL::ERR:
		std::cout << "\n\n" << CLIENT_NAME << " [ERROR] " << message << std::endl << std::endl;
		break;
	default:
		break;
	}
}

void Logger(InputParser::OP_RESULT result) {
	switch (result)
	{
	case InputParser::OP_SUCCESS:
		break;
	case InputParser::INVALID_ADDR:
		Logger(LOGLVL::WARN, "Invalid address given, expecting kernel address in range 0xFFFF0000_00000000 - 0xFFFFFFFF_FFFFFFFF");
		break;
	case InputParser::INVALID_HEX:
		Logger(LOGLVL::WARN, "Invalid hex value given, use format 0xDEADBEEFDEADBEEF");
		break;
	case InputParser::INVALID_SIZE:
		Logger(LOGLVL::WARN, "Size is outside of kernel range 0xFFFF0000_00000000 - 0xFFFFFFFF_FFFFFFFF");
		break;
	case InputParser::ERR_OVERFLOW:
		Logger(LOGLVL::WARN, "Address arithmetic caused overflow!  Invalid range.");
		break;
	default:
		break;
	}
}