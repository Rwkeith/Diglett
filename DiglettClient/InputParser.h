#pragma once


#include <vector>
#include <string>
#include <sstream>
#include <regex>

#define MAX_LINE_LEN 60
#define PROMPT true;
#define EXIT false;

/// <summary>
/// 
/// </summary>
class InputParser {
public:
    std::vector<UINT64> u64Values;

    enum OP_RESULT {
        OP_SUCCESS,
        INVALID_ADDR,
        INVALID_HEX,
        INVALID_SIZE,
        ERR_OVERFLOW
    };
    
    InputParser(char* line) {
        std::string s = line;
        std::stringstream ss(s);
        std::istream_iterator<std::string> begin(ss);
        std::istream_iterator<std::string> end;
        this->tokens = new std::vector<std::string>(begin, end);
        //std::copy(tokens->begin(), tokens->end(), std::ostream_iterator<std::string>(std::cout, "\n"));
    }

    ~InputParser() {
        delete this->tokens;
    }

    const std::string& GetCmdOption(const std::string& option) const {
        std::vector<std::string>::const_iterator itr;
        itr = std::find(this->tokens->begin(), this->tokens->end(), option);
        if (itr != this->tokens->end() && ++itr != this->tokens->end()) {
            return *itr;
        }
        static const std::string empty_string("");
        return empty_string;
    }

    bool CmdOptionExists(const std::string& option) const {
        return std::find((this->tokens->begin() + 1), this->tokens->end(), option)
            != this->tokens->end();
    }
    bool CheckCmd(const std::string& cmd) {
        return this->tokens->front() == cmd;
    }

    static OP_RESULT IsHexStringValid(const std::string& hexStr) {
        if (std::regex_match(hexStr, std::regex("[0][x][a-fA-F0-9]+.*")))
            return OP_SUCCESS;

        return INVALID_HEX;
    }
    
    /// <summary>
    /// Check if address is valid
    /// </summary>
    /// <param name="addr">18 character address</param>
    /// <returns></returns>

    static OP_RESULT IsAddressValid(const std::string& addr) {
        auto searchResults = std::smatch{};
        if (std::regex_match(addr, std::regex("[0][x][a-fA-F0-9]{16}.*")))
            return OP_SUCCESS;

        return INVALID_ADDR;
    }

    OP_RESULT IsLengthValid(UINT64 baseAddr, const std::string& lengthStr) {
        if (IsHexStringValid(lengthStr))
            return INVALID_HEX;

        std::string cpylengthStr = lengthStr.substr(2, lengthStr.length());
        UINT64 addr = ConvertToU64(cpylengthStr.c_str(), cpylengthStr.length());

        // overflow check
        UINT64 maxAddr = 0;
        if (!IsOverflow(&maxAddr, baseAddr, addr)) {
            if (!(KERNEL_MIN_ADDR < maxAddr) && (maxAddr < KERNEL_MAX_ADDR))
                return INVALID_SIZE;
        }
        else
            return ERR_OVERFLOW;
        

        return OP_SUCCESS;
    }

    static OP_RESULT IsOverflow(UINT64* result, UINT64 a, UINT64 b)
    {
        if (a > UINT64_MAX - b)
            return ERR_OVERFLOW;

        *result = a + b;
        return OP_SUCCESS;
    }

    static int Char2int(char input) {
        if (input >= '0' && input <= '9')
            return input - '0';
        if (input >= 'A' && input <= 'F')
            return input - 'A' + 10;
        if (input >= 'a' && input <= 'f')
            return input - 'a' + 10;
    }

    static unsigned char FromHex(char c) {
        switch (c)
        {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E': 
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            break;
        }
        return 0xFF;
    }

    /// <summary>
    /// Converts and stores char arr to U64 
    /// </summary>
    /// <param name="addr"></param>
    /// <param name="len"></param>
    /// <returns>returns the U64 that was just pushed</returns>
    UINT64 ConvertToU64(const char* addr, size_t len) {
        UINT64 pAddr = 0;
        len -= 2;
        for (size_t i = 0; i <= len; i++)
        {
            char test = addr[len - i];
            auto val = FromHex(addr[len - i]);
            auto power = pow(16, i);
            UINT64 signifdigit = (UINT64)pow(16, i) * (UINT64)FromHex(addr[len - i]);
            pAddr += signifdigit;
        }
        return pAddr;
    }

    void PushU64(UINT64 val) {
        u64Values.push_back(val);
    }
private:
    std::vector <std::string> *tokens = nullptr;
};