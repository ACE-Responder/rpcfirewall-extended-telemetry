//https://github.com/leftspace89/pdbparse
#pragma once
#include <string_view>
#include "pdbparsestructs.h"

namespace pdb_parse
{
	uintptr_t get_address_from_symbol(std::string_view function_name, const module_t &module_info, bool is_wow64);
	module_t get_module_info(std::string_view path, bool is_wow64);

	void clear_info();
}


std::string get_pdb_path(const module_t& module_info, bool is_wow64);
