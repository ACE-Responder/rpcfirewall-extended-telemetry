#pragma once

#include <list>
#include <string>
#include <sstream>

#include "IdlType.h"
#include "internalRpcDecompTypeDefs.h"

class IdlType;

class IdlFunction
{
private:
	std::list<IdlType>		m_listArg;
	UINT					m_uOffsetFirstArg;
	UINT					m_numParams;
	PROC_HEADER_T			m_ProcHeader;
	std::wstring			m_ifUuid;
	std::wstring			m_ifName=L"";
	UINT					m_procNum;
	unsigned char*			m_stackTop;
	std::wstring			m_extendedTelemetryJson=L"";
	UINT					m_callerPID=0;

	BOOL					decodeProcHeader();
	BOOL					decodeArguments();

public:
	UINT64					pProcFormatString;
	UINT64					pTypeFormatString;

	IdlFunction(MIDL_SERVER_INFO* serverInfo, const void* typeFormatString, unsigned int procNum, std::wstring ifUuid, unsigned char* stackTop);
	IdlFunction(const void * procFormatString, const void* typeFormatString, unsigned int procNum, std::wstring ifUuid, unsigned char* stackTop, UINT numParams);

	size_t					getNbArguments() const;
	FC_TYPE					getArgType(int argIndex);
	std::wstring			getArgDir(int argIndex);
	std::wstring			getArgOutStr(int argIndex);
	std::wstring			getIfUuid();
	std::wstring			getIfName();
	unsigned char*			getStackTop();
	UINT					getProcNum();
	std::wstring			getExtendedTelemetry();
	void					setCallerPid(int callerPid);
	int						getCallerPid();
};

std::string wtos(const std::wstring& ws);

