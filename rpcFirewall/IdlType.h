#pragma once

#include <unordered_map>
#include "IdlFunction.h"

class IdlFunction;

class IdlType
{
private:
	std::wstring				m_name;
	IdlFunction*				m_pFunction;
	UINT						m_uOffsetInProcFmt;
	UINT						m_uPtrLevel;
	ProcFormatStringParam_U		m_paramDescription;
	UINT32						m_argNbr = 0;
	std::wstring				m_argDir;
	std::wstring				m_outStr = L"";
	FC_TYPE						m_fcType = (FC_TYPE) -1;
	void						incPtrLevel() { m_uPtrLevel++; }
	void						processComplexType(UINT64 pTypeFormatString, unsigned short formatStringOffset);
	void						processSimpleType(FC_TYPE fcType);


public:
	BOOL						isJson = FALSE;

	IdlType(IdlFunction* pFunction, const UINT m_uOffsetInProcFmt);
	BOOL						decode();

	std::wstring				getName() const;
	UINT32						getArgNbr() const;
	FC_TYPE						getFcType() const;
	std::wstring				getDir() const;
	std::wstring				getOutStr() const;

	void						setFcType(FC_TYPE fcType);
};


