#pragma once
#include <Windows.h>


 BOOL __stdcall WrIsSignedExeFile(wchar_t* filename);
 extern "C"
{
	__declspec(dllexport) wchar_t* __stdcall  wrSignatureSubject(LPCWSTR lpFileName, wchar_t* subject);
	__declspec(dllexport)  BOOL __stdcall IsElevated(int prID);
}