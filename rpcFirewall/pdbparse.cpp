//https://github.com/leftspace89/pdbparse
#include "pch.h"
#include <iostream>
#include "pdbparse.h"
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <atlbase.h>
#include <dia2.h>
#include <iomanip>
#include <urlmon.h>
#include <algorithm>
#include <DbgHelp.h>
#pragma comment(lib,"diaguids.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"dbghelp.lib")



struct codeviewInfo_t
{
	ULONG CvSignature;
	GUID Signature;
	ULONG Age;
	char PdbFileName[ANYSIZE_ARRAY];
};

module_t pdb_parse::get_module_info(std::string_view path, bool is_wow64)
{

	const auto file = CreateFileA(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (!file || file == INVALID_HANDLE_VALUE) {
		OutputDebugString(TEXT("Error: pdb_parse::get_module_info - Cannot open module handle"));
		return module_t();
	}

	const auto file_size = GetFileSize(file, nullptr);

	if (!file_size) {
		OutputDebugString(TEXT("Error: pdb_parse::get_module_info - Module file is empty"));
		return module_t();
	}

	auto module_on_disk = std::make_unique<uint8_t[]>(file_size);
	if (!ReadFile(file, (LPVOID)module_on_disk.get(), file_size, nullptr, nullptr)) {
		OutputDebugString(TEXT("Error: pdb_parse::get_module_info - Cannot open module file"));
		return module_t();
	}



	auto dos_header = (IMAGE_DOS_HEADER*)module_on_disk.get();
	auto image_headers = (void*)(module_on_disk.get() + dos_header->e_lfanew);

	auto image_headers32 = (IMAGE_NT_HEADERS32*)image_headers;
	auto image_headers64 = (IMAGE_NT_HEADERS64*)image_headers;

	CloseHandle(file);

	IMAGE_SECTION_HEADER *sections_array = nullptr;
	int section_count = 0;

	std::unique_ptr<uint8_t[]> module_in_memory = nullptr;
	if (is_wow64)
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers32->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers32 + 1);
		section_count = image_headers32->FileHeader.NumberOfSections;
	}
	else
	{

		module_in_memory = std::make_unique<uint8_t[]>(image_headers64->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers64 + 1);
		section_count = image_headers64->FileHeader.NumberOfSections;
	}

	for (int i = 0; i < section_count; i++)
	{
		if (sections_array[i].Characteristics & 0x800)
			continue;

		memcpy_s(module_in_memory.get() + sections_array[i].VirtualAddress, sections_array[i].SizeOfRawData, module_on_disk.get() + sections_array[i].PointerToRawData, sections_array[i].SizeOfRawData);
	}

	return module_t(0, module_on_disk, module_in_memory, dos_header, path, image_headers);
}

static std::unordered_map<std::string, std::pair<std::unordered_map<std::string, uintptr_t>, std::string>, std::hash<std::string>, map_compatator> cached_info;

std::string get_pdb_path(const module_t &module_info, bool is_wow64)
{
	std::string pdb_path;

	static std::string tmp_folder_path;

	auto does_file_exist = [](std::string_view path) { return GetFileAttributesA(path.data()) != INVALID_FILE_ATTRIBUTES; };

	const uintptr_t debug_directory = (is_wow64 ? module_info.ImageHeaders.image_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress : module_info.ImageHeaders.image_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

	if (debug_directory)
	{
		for (auto current_debug_dir = (IMAGE_DEBUG_DIRECTORY*)(module_info.module_in_memory.get() + debug_directory); current_debug_dir->SizeOfData; current_debug_dir++)
		{
			if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;

			const auto codeview_info = (codeviewInfo_t*)(module_info.module_on_disk.get() + current_debug_dir->PointerToRawData);

			std::string pdb_file(codeview_info->PdbFileName);
			std::string path("C:\\Windows\\System32\\");

			//pdb_path = path.append(pdb_file);

			std::stringstream pdb_extention_path;
			pdb_extention_path << codeview_info->PdbFileName << "\\";

			pdb_extention_path << std::setfill('0') << std::setw(8) << std::hex << codeview_info->Signature.Data1 << std::setw(4) << std::hex << codeview_info->Signature.Data2 << std::setw(4) << std::hex << codeview_info->Signature.Data3;

			for (const auto i : codeview_info->Signature.Data4)
				pdb_extention_path << std::setw(2) << std::hex << +i;

			pdb_extention_path << "1\\" << codeview_info->PdbFileName;

			const auto expected_pdb_path = path + pdb_extention_path.str();
			if (does_file_exist(expected_pdb_path))
			{
				pdb_path = expected_pdb_path;
				break;
			}

			CreateDirectoryA((path + codeview_info->PdbFileName).c_str(), nullptr);

			CreateDirectoryA(expected_pdb_path.substr(0, expected_pdb_path.find_last_of('\\')).c_str(), nullptr);

			std::string symbol_server = "http://msdl.microsoft.com/download/symbols/";

			std::wcout << symbol_server.c_str() << std::endl;
			std::wcout << pdb_extention_path.str().c_str() << std::endl;
			const char* url = (symbol_server.append(pdb_extention_path.str())).c_str();
			const char* filename = expected_pdb_path.c_str();
			std::wcout << url << std::endl;
			HRESULT res = URLDownloadToFileA(nullptr, url, filename, 0, nullptr);
			std::cout << std::system_category().message(res) << std::endl;
			if (URLDownloadToFile(nullptr, std::wstring(url,url+strlen(url)).c_str(), std::wstring(filename, filename + strlen(filename)).c_str(), 0, nullptr) != S_OK)
				break;

			if (does_file_exist(expected_pdb_path)) {
				pdb_path = expected_pdb_path;
			}

			break;
		}
	}

	return pdb_path;
}

uintptr_t pdb_parse::get_address_from_symbol(std::string_view function_name)
{
	HANDLE hProc;
	HANDLE hCurrentProc;
	TCHAR szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	hCurrentProc = GetCurrentProcess();
	DuplicateHandle(hCurrentProc, hCurrentProc, hCurrentProc, &hProc, 0, FALSE, DUPLICATE_SAME_ACCESS);
	SymInitialize(hProc, NULL, TRUE);


	if (SymFromName(hProc, function_name.data(), pSymbol)) {

		std::wostringstream woss;
		woss <<std::hex<< pSymbol->Address;
		OutputDebugString(woss.str().c_str());
		woss.clear();
		return pSymbol->Address;
	}

	DWORD error = GetLastError();

	return 0;

}

