//https://github.com/leftspace89/pdbparse
#pragma once
#include <Windows.h>
#include <winnt.h>
#include <cstdint>
#include <string>
#include <memory>

struct module_t
{
	uintptr_t module_base = 0;

	std::unique_ptr<uint8_t[]> module_on_disk = nullptr;

	std::unique_ptr<uint8_t[]> module_in_memory = nullptr;

	IMAGE_DOS_HEADER *dos_header = nullptr;

	std::string path;

	union
	{
		IMAGE_NT_HEADERS32 *image_headers32;
		IMAGE_NT_HEADERS64 *image_headers64;
	} ImageHeaders;

	module_t(uintptr_t module_base, std::unique_ptr<uint8_t[]> &module_on_disk, std::unique_ptr<uint8_t[]> &module_in_memory, IMAGE_DOS_HEADER *dos_header, std::string_view path, void *image_headers)
	{
		this->module_base = module_base;
		this->module_on_disk = std::move(module_on_disk);
		this->module_in_memory = std::move(module_in_memory);
		this->dos_header = dos_header;
		this->path = path;
		this->ImageHeaders.image_headers32 = (IMAGE_NT_HEADERS32*)image_headers;
	}

	operator bool() const { return module_on_disk && module_in_memory && dos_header && ImageHeaders.image_headers32 && !path.empty(); }

	module_t() {}
};

struct map_compatator
{
	bool operator() (const std::string &left, const std::string &right) const { return !_stricmp(left.c_str(), right.c_str()); }
};
