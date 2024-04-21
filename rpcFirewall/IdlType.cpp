#include "pch.h"
#include "nlohmann/json.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <WbemCli.h>

#include "IdlType.h"		
using json = nlohmann::json;

#ifdef _WIN64
	BOOL is64b = TRUE;
#else
	BOOL is64b = FALSE;
#endif



void IdlType::processSimpleType(FC_TYPE fcType) 
{
	switch (fcType)
	{

	case FC_BYTE:
	{
		OutputDebugString(TEXT("FC_BYTE"));
		std::wostringstream woss;
		byte* pArg = reinterpret_cast<byte*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		break;
	}

	case FC_CHAR:
	{
		OutputDebugString(TEXT("FC_CHAR"));
		std::wostringstream woss;
		char* pArg = reinterpret_cast<char*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	case FC_SMALL:
	{
		OutputDebugString(TEXT("FC_SMALL"));
		std::wostringstream woss;
		small* pArg = reinterpret_cast<small*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	case FC_WCHAR:
	{
		OutputDebugString(TEXT("FC_WCHAR"));
		std::wostringstream woss;
		WCHAR* pArg = reinterpret_cast<WCHAR*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	case FC_SHORT:
	{
		OutputDebugString(TEXT("FC_SHORT"));
		std::wostringstream woss;
		short* pArg = reinterpret_cast<short*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	case FC_USHORT:
	{
		OutputDebugString(TEXT("FC_USHORT"));
		std::wostringstream woss;
		unsigned short* pArg = reinterpret_cast<unsigned short*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	case FC_LONG:
	{
		OutputDebugString(TEXT("FC_LONG"));
		std::wostringstream woss;
		long* pArg = reinterpret_cast<long*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}

	case FC_ULONG:
	{
		OutputDebugString(TEXT("FC_LONG"));
		std::wostringstream woss;
		unsigned long* pArg = reinterpret_cast<unsigned long*>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	default:
		std::wostringstream woss;
		woss << std::hex << "Type Not Implemented: " << fcType << std::endl;
		OutputDebugString(woss.str().c_str());
		woss.clear();
		break;
	}



}

void IdlType::processComplexType(
	UINT64 pTypeFormatString,
	unsigned short formatStringOffset)
{
	BYTE bFcType;
	FC_TYPE fcType;

	memcpy(&bFcType, (VOID*)(pTypeFormatString + formatStringOffset), sizeof(bFcType));
	fcType = (FC_TYPE)bFcType;


	switch (fcType)

	{
	case FC_BYTE:
	case FC_CHAR:
	case FC_SMALL:
	case FC_WCHAR:
	case FC_SHORT:
	case FC_USHORT:
	case FC_LONG:
	case FC_ULONG:
	case FC_FLOAT:
	case FC_HYPER:
	case FC_DOUBLE:
	case FC_ENUM16:
	case FC_ENUM32:
	case FC_ERROR_STATUS_T:
	case FC_IGNORE:
	case FC_INT3264:
	case FC_UINT3264:
		processSimpleType(fcType);
		break;
	//case FC_C_CSTRING:
	case FC_C_WSTRING:
	{
		OutputDebugString(TEXT("FC_C_WSTRING"));
		std::wostringstream woss;

		wchar_t** pArg = reinterpret_cast<wchar_t**>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
		if (pArg) {
			woss << *pArg;
			m_outStr = woss.str();
		}
		OutputDebugString(woss.str().c_str());
		break;
	}
	//case FC_WSTRING:
	//case FC_CSTRING:
	//case FC_STRUCT:
	//case FC_PSTRUCT: 
	case FC_CSTRUCT:
	{
		OutputDebugString(TEXT("FC_CSTRUCT"));
		ConfStructHeader_t structHeader;
		UINT64 pArrayDescription;
		UINT64 pMemberLayout;

		memcpy(&structHeader, (VOID*)(pTypeFormatString + formatStringOffset), sizeof(structHeader));

		//Conformant struct for IWbemService are BSTR
		std::wostringstream woss;
		if (m_pFunction->getIfName()==L"IWbemServices") {
			std::wostringstream woss;
			wchar_t** pArg = reinterpret_cast<wchar_t**>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
			if (pArg) {
				woss << *pArg;
				m_outStr = woss.str();
			}

			OutputDebugString(woss.str().c_str());
		}
		break;
	}

	//case FC_CPSTRUCT:
	//case FC_CVSTRUCT:
	//case FC_BOGUS_STRUCT:
	//case FC_HARD_STRUCT:
	case FC_RP:
	case FC_UP:
	case FC_FP:
	{
		OutputDebugString(TEXT("FC_<pointer>"));
		BYTE bRead;
		CommonPtrSimple_t simplePtr;
		CommonPtrComplex_t complexPtr;
		UINT64 pComplexType;

		if (m_uPtrLevel > 1) {
			processSimpleType(NOT_IMPLEMENTED);
			return;
		}

		incPtrLevel();
		memcpy(&bRead, (VOID*)(pTypeFormatString+ formatStringOffset + 1),sizeof(bRead));
		if (bRead & FC_SIMPLE_POINTER) {
			memcpy(&simplePtr, (VOID*)(pTypeFormatString+formatStringOffset), sizeof(simplePtr));
			if ((FC_TYPE)simplePtr.simple_type == FC_C_CSTRING) {
				processSimpleType((FC_TYPE)simplePtr.simple_type);
			}
			else if ((FC_TYPE)simplePtr.simple_type == FC_C_WSTRING) {
				OutputDebugString(TEXT("FC_C_WSTRING"));
				std::wostringstream woss;
				if (!*(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset))
					return;
				wchar_t** pArg = reinterpret_cast<wchar_t**>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
				if (pArg) {
					woss << *pArg;
					m_outStr = woss.str();
				}
				OutputDebugString(woss.str().c_str());
			}
			else {
				processSimpleType((FC_TYPE)simplePtr.simple_type);
			}
			return;
		}

		memcpy(&complexPtr, (VOID*)(pTypeFormatString+ formatStringOffset),sizeof(complexPtr));
		pComplexType = (UINT64)(pTypeFormatString + formatStringOffset) + sizeof(complexPtr.pointerType) + sizeof(complexPtr.pointer_attributes)+complexPtr.offset_to_complex_description;
		processComplexType(pComplexType, 0);

		break;
	}
	case FC_USER_MARSHAL:
	{
		std::wostringstream wss;
		wss << "FC_USER_MARSHAL" << std::endl;
		OutputDebugString(wss.str().c_str());
		wss.clear();
		UserMarshal_t userMarshal;
		UINT64 pUserMarshalTarget = NULL;
		memcpy(&userMarshal, (void*)(pTypeFormatString + formatStringOffset), sizeof(userMarshal));
		pUserMarshalTarget = (UINT64)(pTypeFormatString + formatStringOffset) + FIELD_OFFSET(UserMarshal_t, offset_to_the_transmitted_type) + userMarshal.offset_to_the_transmitted_type;
		processComplexType(pUserMarshalTarget, 0);
		break;
	}

	case FC_IP:
	{
		OutputDebugString(L"FC_IP");
		if (m_pFunction->getIfName()==L"IWbemServices" && 
			(m_pFunction->getProcNum() == 24 && m_argNbr == 5) ||//ExecMethod
			(m_pFunction->getProcNum() == 25 && m_argNbr == 5) ||
			(m_pFunction->getProcNum() == 14 && m_argNbr == 1) ||//PutInstance
			(m_pFunction->getProcNum() == 15 && m_argNbr == 1)
			) {

			IWbemClassObject** ppInParams = reinterpret_cast<IWbemClassObject**>(m_pFunction->getStackTop() + m_paramDescription.oif_Format.stack_offset);
			IWbemClassObject* pInParams = *ppInParams;

			SAFEARRAY* pNames = NULL;
			HRESULT hr = pInParams->GetNames(NULL,WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY,NULL,&pNames);

			if (SUCCEEDED(hr)) {
				isJson = TRUE;
				json j;
				long lLower, lUpper; 
				BSTR pName = NULL;
				SafeArrayGetLBound(pNames, 1, &lLower);
				SafeArrayGetUBound(pNames, 1, &lUpper);
				for (long i = lLower; i <= lUpper; i++) {
					hr = SafeArrayGetElement(pNames, &i, &pName);
					if (SUCCEEDED(hr)) {
						VARIANT cmd;
						hr = pInParams->Get(pName, 0, &cmd, NULL, NULL);
						if (SUCCEEDED(hr) && V_VT(&cmd)==VT_BSTR) {
							std::wostringstream wossName;
							std::wostringstream wossArg;
							wossName << pName;
							wossArg << V_BSTR(&cmd);
							j[wtos(pName)] = wtos(wossArg.str());
						}
					}
					SysFreeString(pName);
				}
				std::wostringstream woss;
				woss << j.dump().c_str();
				m_outStr = woss.str();
			}
			SafeArrayDestroy(pNames);
		}

		break;
	}
	default:
		std::wostringstream wss;
		wss << "Type Not Implemented: " << std::hex << fcType << std::endl;
		OutputDebugString(wss.str().c_str());
		wss.clear();
		break;
	}
}


IdlType::IdlType(IdlFunction* pFunction, const UINT m_uOffsetInProcFmt):
	m_pFunction(pFunction),
	m_uOffsetInProcFmt(m_uOffsetInProcFmt),
	m_uPtrLevel(0)
{

}

BOOL IdlType::decode()
{
		std::wostringstream inout;

		memcpy(&m_paramDescription,(VOID*)(m_pFunction->pProcFormatString+m_uOffsetInProcFmt), sizeof(m_paramDescription));

		if(is64b)	m_argNbr = m_paramDescription.oif_Format.stack_offset / VIRTUAL_STACK_OFFSET_GRANULARITY_64B;
		else		m_argNbr = m_paramDescription.oif_Format.stack_offset / VIRTUAL_STACK_OFFSET_GRANULARITY_32B;


		std::wostringstream wss;
		wss << "arg_number: "  << std::hex << m_argNbr << std::endl;
		OutputDebugString(wss.str().c_str());
		wss.clear();

		if (m_paramDescription.oif_Format.paramAttributes.IsIn) {
			inout << "in";
		}
		if (m_paramDescription.oif_Format.paramAttributes.IsOut) {
			inout << "out";
		}
		m_argDir = inout.str();
		
		if (m_argDir == L"in") {
			if (m_paramDescription.oif_Format.paramAttributes.IsBasetype) {
				processSimpleType((FC_TYPE)m_paramDescription.oif_Format.paramType.base_type_format_char.type_format_char);
			}
			else {
				processComplexType(m_pFunction->pTypeFormatString, m_paramDescription.oif_Format.paramType.other_type_offset);
			}
		}



	return TRUE;

}


std::wstring IdlType::getName() const
{
	return m_name;
}

UINT32 IdlType::getArgNbr() const
{
	return m_argNbr;
}

void IdlType::setFcType(FC_TYPE fcType)
{
	m_fcType = fcType;
}

FC_TYPE IdlType::getFcType() const
{
	return m_fcType;
}

std::wstring IdlType::getDir() const
{
	return m_argDir;
}


std::wstring IdlType::getOutStr() const
{
	return m_outStr;
}

