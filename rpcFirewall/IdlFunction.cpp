#include "pch.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <iostream>
#include <iomanip>

#include "wellKnownInterfaces.h"
#include "internalRpcDecompTypeDefs.h"
#include "IdlFunction.h"
using json = nlohmann::json;


std::string wtos(const std::wstring &ws)
{
	if (ws.empty())
		return std::string();
	int size = WideCharToMultiByte(CP_UTF8, 0, &ws[0], ws.length(), NULL, 0, NULL, NULL);
	std::string s(size, 0);
	WideCharToMultiByte(CP_UTF8, 0, &ws[0], ws.length(), &s[0], size, NULL, NULL);
	return s;
}

IdlFunction::IdlFunction(MIDL_SERVER_INFO* serverInfo, const void * typeFormatString, unsigned int procNum, std::wstring ifUuid, unsigned char * stackTop):
m_procNum(procNum),
m_ifUuid(ifUuid),
m_stackTop(stackTop)
{

	if (!ifUuid.empty()) {
		if (known_iids.find(ifUuid) != known_iids.end()) {
			m_ifName = known_iids.at(ifUuid);
		}
	}

	memset(&m_ProcHeader, 0, sizeof(m_ProcHeader));

	unsigned short fmtStringOffset = serverInfo->FmtStringOffset[procNum];
	auto offsetProcString = (void*)(serverInfo->ProcString + fmtStringOffset);
	memcpy(&this->pProcFormatString, &offsetProcString, sizeof(this->pProcFormatString));

	memcpy(&this->pTypeFormatString, &typeFormatString, sizeof(this->pTypeFormatString));

	decodeProcHeader();
	decodeArguments();
}


IdlFunction::IdlFunction(const void * procFormatString, const void * typeFormatString, unsigned int procNum, std::wstring ifUuid, unsigned char * stackTop, UINT numParams):
m_procNum(procNum),
m_ifUuid(ifUuid),
m_stackTop(stackTop),
m_numParams(numParams)
{

	if (!ifUuid.empty()) {
		if (known_iids.find(ifUuid) != known_iids.end()) {
			m_ifName = known_iids.at(ifUuid);
		}
	}

	memcpy(&this->pProcFormatString, &procFormatString, sizeof(this->pProcFormatString));

	memcpy(&this->pTypeFormatString, &typeFormatString, sizeof(this->pTypeFormatString));

	m_uOffsetFirstArg = 0;

	decodeArguments();

}

BOOL IdlFunction::decodeProcHeader()
{

	UINT uOffsetInProcFmtString = 0;

	memcpy(&this->m_ProcHeader.oiHeader.beginning,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.oiHeader.beginning));

	uOffsetInProcFmtString += sizeof(m_ProcHeader.oiHeader.beginning);

	if ((this->m_ProcHeader.oiHeader.beginning.bOi_flags & Oi_HAS_RPCFLAGS) == Oi_HAS_RPCFLAGS)
	{
		memcpy(&this->m_ProcHeader.oiHeader.dwRpc_flags,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.oiHeader.dwRpc_flags));
		uOffsetInProcFmtString += sizeof(this->m_ProcHeader.oiHeader.dwRpc_flags);
	}

	memcpy(&this->m_ProcHeader.oiHeader.end,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.oiHeader.end));
	std::cout << "stack size: "<<this->m_ProcHeader.oiHeader.end.wStack_size << std::endl;

	uOffsetInProcFmtString += sizeof(this->m_ProcHeader.oiHeader.dwRpc_flags);

	if (this->m_ProcHeader.oiHeader.beginning.bHandle_type == FC_EXPLICIT_HANDLE)
	{
		memcpy(&this->m_ProcHeader.explicitHandle,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), EXPLICIT_HANDLE_MIN_SIZE);
		switch (this->m_ProcHeader.explicitHandle.htype)
		{
		case FC_BIND_PRIMITIVE:
			uOffsetInProcFmtString+= EXPLICIT_HANDLE_PRIMITIVE_SIZE;
			break;

		case FC_BIND_GENERIC:
			memcpy(&this->m_ProcHeader.explicitHandle,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), EXPLICIT_HANDLE_GENERIC_SIZE);
			uOffsetInProcFmtString+= EXPLICIT_HANDLE_GENERIC_SIZE;
			break;

		case FC_BIND_CONTEXT:
			memcpy(&this->m_ProcHeader.explicitHandle,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), EXPLICIT_HANDLE_CONTEXT_SIZE);
			uOffsetInProcFmtString+= EXPLICIT_HANDLE_CONTEXT_SIZE;
			break;

		default:
			RPC_ERROR_FN("invalid explicit handle type\n");
			return DS_ERR_INVALID_DATA;
		}

	}

	memcpy(&this->m_ProcHeader.oifheader,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.oifheader));
	uOffsetInProcFmtString += sizeof(this->m_ProcHeader.oifheader);

	if (this->m_ProcHeader.oifheader.interpreter_opt_flag.HasExtensions)
	{

	memcpy(&this->m_ProcHeader.win2KextHeader,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.win2KextHeader));
	//uOffsetInProcFmtString += sizeof(this->m_ProcHeader.win2KextHeader);
		switch (this->m_ProcHeader.win2KextHeader.extension_version)
		{
		case WIN2K_EXT_HEADER_32B_SIZE:

	memcpy(&this->m_ProcHeader.win2KextHeader.extension_version,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.win2KextHeader.extension_version));
	uOffsetInProcFmtString += WIN2K_EXT_HEADER_32B_SIZE;

			break;
		case WIN2K_EXT_HEADER_64B_SIZE:

	memcpy(&this->m_ProcHeader.win2KextHeader.extension_version,(VOID*)(this->pProcFormatString+uOffsetInProcFmtString), sizeof(this->m_ProcHeader.win2KextHeader.extension_version));
	uOffsetInProcFmtString += WIN2K_EXT_HEADER_64B_SIZE;
			break;

		default:
			RPC_ERROR_FN("invalid win32k header len");
			return DS_ERR_INVALID_DATA;
		}
	}


	m_uOffsetFirstArg =   uOffsetInProcFmtString;

	this->m_numParams = m_ProcHeader.oifheader.number_of_param;

	return TRUE;
}

BOOL IdlFunction::decodeArguments()
{
	UINT uOffsetArg = 0;

	uOffsetArg = m_uOffsetFirstArg;

	for (unsigned int i = 0; i < this->m_numParams; i++) {
		IdlType idlArg(this, uOffsetArg);
		idlArg.decode();
		m_listArg.push_back(idlArg);

		uOffsetArg += OIF_PARAM_SIZE;
	}

	return TRUE;

}

size_t IdlFunction::getNbArguments() const
{
	return (size_t)m_numParams;
}

unsigned char* IdlFunction::getStackTop()
{
	return m_stackTop;
}

std::wstring IdlFunction::getIfUuid()
{
	return m_ifUuid;
}

std::wstring IdlFunction::getIfName()
{
	return m_ifName;
}

UINT IdlFunction::getProcNum()
{
	return m_procNum;
}


FC_TYPE IdlFunction::getArgType(int argIndex)
{
	IdlType arg = *std::next(m_listArg.begin(), argIndex);
	return arg.getFcType();
}

std::wstring IdlFunction::getArgDir(int argIndex)
{
	IdlType arg = *std::next(m_listArg.begin(), argIndex);
	return arg.getDir();
}

std::wstring IdlFunction::getArgOutStr(int argIndex)
{
	IdlType arg = *std::next(m_listArg.begin(), argIndex);
	return arg.getOutStr();
}

	void					setCallerPid(int callerPid);
	int						getCallerPid();
void IdlFunction::setCallerPid(int callerPid)
{
	m_callerPID = callerPid;
}

int IdlFunction::getCallerPid()
{
	return m_callerPID;
}

std::wstring IdlFunction::getExtendedTelemetry()
{
    std::wostringstream woss;
	json j;

	if (m_callerPID) {
		j["ClientPID"] = m_callerPID;
	}

    if (!m_ifName.empty()) {
		j["KnownInterface"] = wtos(m_ifName);
        if (opnumMap.find(m_ifUuid) != opnumMap.end()) {
            auto ifOpnums = opnumMap.at(m_ifUuid);
            if (ifOpnums.find(m_procNum) != ifOpnums.end()) {
				auto opMethod = ifOpnums.at(m_procNum);
				j["Method"] = wtos(opMethod);
            }
        }
    }

    for (std::list<IdlType>::iterator arg = m_listArg.begin(); arg != m_listArg.end(); arg++) {
        if (!arg->getOutStr().empty()) {

			std::ostringstream argoss;
            argoss << "arg_" << arg->getArgNbr();
			auto argStr = arg->getOutStr();
			if (arg->isJson) {
				j[argoss.str().c_str()] = json::parse(wtos(argStr));
			}
			else {
				j[argoss.str().c_str()] = wtos(argStr);
			}
        }
    }

	woss << j.dump(2).c_str();
    return woss.str();
}
