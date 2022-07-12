#include "Windows.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <io.h>
#include <map>

static std::wstring iconPath;
static std::wstring filePath;

std::wstring s2ws(const std::string& s);
double getEntropy(LPVOID fileData, DWORD fileSize);
void Init_();


int main() {

	Init_();

	std::vector<char*> tableImport;
	LPCWSTR fileName = filePath.c_str();
	LPCWSTR icoName = iconPath.c_str();
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	// open file
	file = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) printf("Could not read file");

	// allocate heap
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, fileSize);

	// read file bytes to memory
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);
	double entropy_exe = getEntropy(fileData, fileSize);
	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);

	// get offset to first section headeer
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	if (importSection == NULL)
	{
		std::cout << "This file hasn't imports DLL";
	}
	else
	{

		// get file offset to import table
		rawOffset = (DWORD)fileData + importSection->PointerToRawData;

		// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

		printf("\n******* DLL IMPORTS *******\n");
		for (; importDescriptor->Name != 0; importDescriptor++) {
			// imported dll modules
			DWORD nameLibrary = rawOffset + (importDescriptor->Name - importSection->VirtualAddress);
			char* str = (char*)nameLibrary;
			tableImport.push_back(str);
			printf("\t%s\n", nameLibrary);
			thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
			thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));
		}

		char symW[2] = { 'w', 'W' };
		int count = 0;
		for (int i = 0; i < tableImport.size(); i++)
		{
			for (int j = 0; j < sizeof(tableImport[i]) / sizeof(tableImport[i][0]); j++)
			{
				if (tableImport[i][j] == symW[0] || tableImport[i][j] == symW[1])
				{
					count++;
					break;
				}
			}
		}
		printf("\n******* Count DLL with 'w' *******\n\t%d", count);
	}
	CloseHandle(file);

	file = CreateFile(icoName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// allocate heap
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, fileSize);

	// read file bytes to memory
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);
	double entropy_ico = getEntropy(fileData, fileSize);
	HANDLE hResource;
	hResource = BeginUpdateResource(fileName, FALSE);
	if (NULL != hResource)
	{
		
		if (UpdateResource(hResource, RT_ICON, (LPCWSTR)file, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)fileData, fileSize))
		{
			EndUpdateResource(hResource, FALSE);
		}
	}

	std::cout << "\n******* Entropy of file is: *******\n\t" << entropy_exe << std::endl;
	std::cout << "\n******* Entropy of ico is: *******\n\t" << entropy_ico << std::endl;

	return 0;
}

void Init_()
{
	std::string stemp;
	std::cout << "Enter full path of file:  ";
	std::cin >> stemp;
	filePath = s2ws(stemp);
	std::cout << std::endl;
	std::cout << "Enter full path of icon:  ";
	std::cin >> stemp;
	iconPath = s2ws(stemp);
	std::cout << std::endl;
}

double getEntropy(LPVOID fileData, DWORD fileSize)
{
	BYTE* fileBuf = new BYTE[fileSize];
	memcpy(fileBuf, fileData, fileSize);
	double entropy = 0;
	std::map<char, int> freq;
	for (int i = 0; i < fileSize; i++)
	{
		freq[fileBuf[i]]++;
	}
	for (std::pair<char, int> p : freq)
	{
		double freq = static_cast<double>(p.second) / fileSize;
		entropy += freq * log2(freq);
	}
	entropy *= -1;
	
	return entropy;
}

std::wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}