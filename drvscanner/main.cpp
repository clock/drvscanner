#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include "scanner.h"
#include "utils.h"

namespace fs = std::filesystem;

std::vector<std::string> targetImports = { "MmCopyVirtualMemory" };

class DriverInfo
{
public:
    DriverInfo(const fs::path &driverPath, const std::vector<std::string> &imports)
        : driverPath(driverPath)
        , imports(imports)
    {
    }

    fs::path driverPath;
    std::vector<std::string> imports;
};

std::vector<DriverInfo> resultingDrivers;

bool DriverInfoSortComparison(const DriverInfo &d1, const DriverInfo &d2)
{
    return d1.imports.size() > d2.imports.size();
}

std::string extractPath(const std::string& line) 
{
    std::size_t start = line.find('"');
    std::size_t end = line.find('"', start + 1);
    if (start != std::string::npos && end != std::string::npos)
        return line.substr(start + 1, end - start - 1);
    return "";
}

int main(int argc, const char** argv)
{
    // check arguments
    if (argc != 2) 
    {
        std::cerr << "Usage: " << argv[0] << " <path to .efu file>" << std::endl;
        return 1;
    }

    std::string efuFilePath = argv[1];
    //std::string efuFilePath = "C:/Users/15195/Downloads/testexport.efu";

    std::ifstream efuFile(efuFilePath);
    if (!efuFile.is_open()) 
    {
        std::cerr << "Error: Failed to open .efu file." << std::endl;
        return 1;
    }

    std::vector<std::string> drivers;
    std::string line;
    while (std::getline(efuFile, line)) 
    {
        std::string path = extractPath(line);
        if (!path.empty()) 
        {
            std::string extension = path.substr(path.find_last_of(".") + 1);
            if (extension == "sys")
                drivers.push_back(path);
        }
    }

    efuFile.close();

    std::cout << "[~] Found " << drivers.size() << " drivers." << std::endl;

    std::ofstream logFile;
    logFile.open("log.txt", std::ios::out);
    if (!logFile.is_open())
    {
        std::cout << "Unable to open log file." << std::endl;
        return 0;
    }

    std::cout << "[~] Searching for the following imports: " << std::endl;
    for (int i = 0; i < targetImports.size(); i++)
    {
        std::cout << "  (" << i << ") " << targetImports[i] << std::endl;
    }

    std::vector<std::string> resultingDriverFileNames;

    for (std::string driverPathStr : drivers)
    {
        std::vector<std::string> foundImports = scanner::FindPEImports(driverPathStr, targetImports);
        std::sort(foundImports.begin(), foundImports.end());
        if (foundImports.empty()) { continue; }
        fs::path driverPath = fs::path(driverPathStr);
        resultingDrivers.push_back(DriverInfo(driverPathStr, foundImports));
        resultingDriverFileNames.push_back(driverPath.filename().string());

    }

    std::sort(resultingDrivers.begin(), resultingDrivers.end(), DriverInfoSortComparison);

    size_t longestDriverFileNameLength = utils::GetLongestStringLength(resultingDriverFileNames);
    for (const DriverInfo& driverInfo : resultingDrivers)
    {
        std::string fileName = driverInfo.driverPath.filename().string();
        std::string logText = fileName;

        for (size_t i = 0; i < longestDriverFileNameLength - fileName.length() + 5; i++)
        {
            logText += " ";
        }

        logText += "[";

        for (const std::string& importName : driverInfo.imports)
        {
            std::stringstream appendText;
            appendText << importName;
            if (driverInfo.imports.back() == importName)
            {
                appendText << "] (" << driverInfo.imports.size() << ")";
            }
            else
            {
                appendText << " / ";
            }

            logText = logText + appendText.str();
        }

        logFile << logText << std::endl;
    }

    logFile.close();

    std::cout << "[~] Done, found " << resultingDrivers.size() << " potentially vulnerable drivers." << std::endl;

    return 0;
}