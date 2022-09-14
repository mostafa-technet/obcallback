#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <mscat.h>
#include <stdio.h>


#pragma comment (lib, "Crypt32")
#pragma comment (lib, "winTrust")

// the Authenticode Signature is encode in PKCS7
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define MAXPATH 2048
// Information structure of authenticode sign
typedef struct
{
	LPWSTR lpszProgramName;
	LPWSTR lpszPublisherLink;
	LPWSTR lpszMoreInfoLink;

	DWORD cbSerialSize;
	LPBYTE lpSerialNumber;
	LPTSTR lpszIssuerName;
	LPTSTR lpszSubjectName;
}
SPROG_SIGNATUREINFO, * PSPROG_SIGNATUREINFO;


LPWSTR AllocateAndCopyWideString(LPCWSTR inputString)
{
	LPWSTR outputString = NULL;

	// allocate the memory
	outputString = (LPWSTR)VirtualAlloc(NULL, (wcslen(inputString) + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);

	// copy
	if (outputString != NULL)
	{
		lstrcpyW(outputString, inputString);
	}

	return outputString;
}
#pragma warning (disable:4706)
VOID GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_SIGNATUREINFO pInfo)
{
	PSPC_SP_OPUS_INFO OpusInfo = NULL;
	DWORD dwData = 0;

	////printf("\n400\n");
		// query SPC_SP_OPUS_INFO_OBJID OID in Authenticated Attributes
	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			// get the length of SPC_SP_OPUS_INFO
			if (!CryptDecodeObject(ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				NULL,
				&dwData))
			{
				fprintf(stderr, "Error!10\n");
				return;
			}
			////printf("\n41\n");
			// allocate the memory for SPC_SP_OPUS_INFO
			if (!(OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData)))
			{
				fprintf(stderr, "Error!11\n");
				return;
			}
			// get SPC_SP_OPUS_INFO structure
			if (!CryptDecodeObject(ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				OpusInfo,
				&dwData))
			{
				fprintf(stderr, "Error!12\n");
				return;
			}
			////printf("\n42\n");
			// copy the Program Name of SPC_SP_OPUS_INFO to the return variable
			if (OpusInfo->pwszProgramName)
			{
				pInfo->lpszProgramName = AllocateAndCopyWideString(OpusInfo->pwszProgramName);
			}
			else
				pInfo->lpszProgramName = NULL;

			// copy the Publisher Info of SPC_SP_OPUS_INFO to the return variable
			if (OpusInfo->pPublisherInfo)
			{
				switch (OpusInfo->pPublisherInfo->dwLinkChoice)
				{
				case SPC_URL_LINK_CHOICE:
					pInfo->lpszPublisherLink = AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
					break;

				case SPC_FILE_LINK_CHOICE:
					pInfo->lpszPublisherLink = AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
					break;

				default:
					pInfo->lpszPublisherLink = NULL;
					break;
				}
			}
			else
			{
				pInfo->lpszPublisherLink = NULL;
			}

			// copy the More Info of SPC_SP_OPUS_INFO to the return variable
			if (OpusInfo->pMoreInfo)
			{
				switch (OpusInfo->pMoreInfo->dwLinkChoice)
				{
				case SPC_URL_LINK_CHOICE:
					pInfo->lpszMoreInfoLink = AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
					break;

				case SPC_FILE_LINK_CHOICE:
					pInfo->lpszMoreInfoLink = AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
					break;

				default:
					pInfo->lpszMoreInfoLink = NULL;
					break;
				}
			}
			else
			{
				pInfo->lpszMoreInfoLink = NULL;
			}

			break; // we have got the information, break
		}
	}

}


VOID GetCertificateInfo(HCERTSTORE hStore, PCMSG_SIGNER_INFO pSignerInfo, PSPROG_SIGNATUREINFO pInfo)
{
	PCCERT_CONTEXT pCertContext = NULL;


	CERT_INFO CertInfo;
	DWORD dwData;

	// query Signer Certificate in Certificate Store
	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;

	if (!(pCertContext = CertFindCertificateInStore(hStore,
		ENCODING, 0, CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo, NULL)))
	{
		fprintf(stderr, "Error!23\n");
		return;
	}
	////printf("%x", GetLastError());
	dwData = pCertContext->pCertInfo->SerialNumber.cbData;

	// SPROG_SIGNATUREINFO.cbSerialSize
	pInfo->cbSerialSize = dwData;

	// SPROG_SIGNATUREINFO.lpSerialNumber
	pInfo->lpSerialNumber = (LPBYTE)VirtualAlloc(NULL, dwData, MEM_COMMIT, PAGE_READWRITE);
	if (pInfo->lpSerialNumber == NULL)
		goto cleanup;
	memcpy(pInfo->lpSerialNumber, pCertContext->pCertInfo->SerialNumber.pbData, dwData);

	// SPROG_SIGNATUREINFO.lpszIssuerName

		// get the length of Issuer Name
	if (!(dwData = CertGetNameString(pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG, NULL, NULL, 0)))
	{
		fprintf(stderr, "Error!24\n");
		return;
	}
	////printf("\n51\n");
	// allocate the memory
	if (!(pInfo->lpszIssuerName = (LPTSTR)VirtualAlloc(NULL, dwData * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE)))
		fprintf(stderr, "Error!244\n");

	// get Issuer Name
	if (!(CertGetNameString(pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG, NULL, pInfo->
		lpszIssuerName, dwData)))
	{
		fprintf(stderr, "Error!25\n");
		return;
	}
	////printf("\n52\n");

	//get the length of Subject Name
	if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
	{
		fprintf(stderr, "Error!26\n");
		return;
	}

	// allocate the memory
	if (!(pInfo->lpszSubjectName = (LPTSTR)VirtualAlloc(NULL, dwData * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE)))
	{
		fprintf(stderr, "Error!27\n");
		return;
	}
	// get Subject Name
	if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pInfo->lpszSubjectName, dwData)))
	{
		fprintf(stderr, "Error!28\n");
		return;
	}
cleanup:
	return;

}


BOOL GetAuthenticodeInformation(LPCTSTR lpszFileName, PSPROG_SIGNATUREINFO pInfo)
{
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	DWORD dwSignerInfo = 0;

	BOOL bRet = FALSE;


	// as CryptQueryObject() only accept WCHAR file name, convert first
	WCHAR wszFileName[MAXPATH];
	ZeroMemory(wszFileName, MAXPATH);
#ifdef UNICODE
	if (!lstrcpynW(wszFileName, lpszFileName, MAXPATH))
	{
		fprintf(stderr, "Error!1\n");
		return bRet;
	}
#else
	if (mbstowcs(wszFileName, lpszFileName, MAXPATH) == -1)
		fprintf(stderr, "Error!2\n");
#endif
	//Retrieve the Message Handle and Store Handle
	DWORD dwEncoding, dwContentType, dwFormatType;
	if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wszFileName,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding,
		&dwContentType, &dwFormatType, &hStore,
		&hMsg, NULL))
	{
		fprintf(stderr, "Error!3\n0x%ux\n%ls\n", GetLastError(), wszFileName);
		//system("taskkill.exe /f /im scanuser.exe");
		//exit(1);
		return bRet;
	}
	////printf("1\n");
	//Get the length of SignerInfo
	if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo))
	{
		fprintf(stderr, "Error!4\n");
		return bRet;
	}
	////printf("2\n");
	// allocate the memory for SignerInfo
	if (!(pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo)))
	{
		fprintf(stderr, "Error!5\n");
		return bRet;
	}
	////printf("3\n");
	// get the SignerInfo
	int fResult = CryptMsgGetParam(hMsg,
		CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID)pSignerInfo,
		&dwSignerInfo);
	if (!fResult)
	{
		_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
		return bRet;

	}
	//if(pSignerInfo != NULL)
	////printf("*%d\n",pSignerInfo->AuthAttrs.cAttr);
	////printf("4\n");
	//get the Publisher from SignerInfo
	GetProgAndPublisherInfo(pSignerInfo, pInfo);
	////printf("5\n");
	//get the Certificate from SignerInfo
	GetCertificateInfo(hStore, pSignerInfo, pInfo);
	////printf("6\n");
	bRet = TRUE;

	return bRet;
}
#define BUFSZ 2048


DWORD VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
	_In_ HANDLE FileHandle,
	_In_ BOOL UseStrongSigPolicy)
{
	DWORD Error = ERROR_SUCCESS;
	BOOL WintrustCalled = FALSE;
	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData;
	WINTRUST_FILE_INFO FileInfo;
	WINTRUST_SIGNATURE_SETTINGS SignatureSettings;
	CERT_STRONG_SIGN_PARA StrongSigPolicy;

	// Setup data structures for calling WinVerifyTrust 
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileInfo.hFile = FileHandle;
	FileInfo.pcwszFilePath = FileName;
	WintrustData.pFile = &FileInfo;

	// 
	// First verify the primary signature (index 0) to determine how many secondary signatures 
	// are present. We use WSS_VERIFY_SPECIFIC and dwIndex to do this, also setting  
	// WSS_GET_SECONDARY_SIG_COUNT to have the number of secondary signatures returned. 
	// 
	SignatureSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
	SignatureSettings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
	SignatureSettings.dwIndex = 0;
	WintrustData.pSignatureSettings = &SignatureSettings;

	if (UseStrongSigPolicy != FALSE)
	{
		StrongSigPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
		StrongSigPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
		StrongSigPolicy.pszOID = szOID_CERT_STRONG_SIGN_OS_CURRENT;
		WintrustData.pSignatureSettings->pCryptoPolicy = &StrongSigPolicy;
	}

	//wprintf(L"Verifying primary signature... ");
	Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	WintrustCalled = TRUE;
	if (Error != ERROR_SUCCESS)
	{
		//PrintError(Error);
		goto Cleanup;
	}

	//wprintf(L"Success!\n");

	//wprintf(L"Found %d secondary signatures\n", WintrustData.pSignatureSettings->cSecondarySigs);

	// Now attempt to verify all secondary signatures that were found 
	for (DWORD x = 1; x <= WintrustData.pSignatureSettings->cSecondarySigs; x++)
	{
		//wprintf(L"Verify secondary signature at index %d... ", x);

		// Need to clear the previous state data from the last call to WinVerifyTrust 
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			//No need to call WinVerifyTrust again 
			WintrustCalled = FALSE;
			//PrintError(Error);
			goto Cleanup;
		}

		WintrustData.hWVTStateData = NULL;

		// Caller must reset dwStateAction as it may have been changed during the last call 
		WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustData.pSignatureSettings->dwIndex = x;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			//PrintError(Error);
			goto Cleanup;
		}

		//wprintf(L"Success!\n");
	}

Cleanup:

	// 
	// Caller must call WinVerifyTrust with WTD_STATEACTION_CLOSE to ///free memory 
	// allocate by WinVerifyTrust 
	// 
	if (WintrustCalled != FALSE)
	{
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	}

	return Error;
}


DWORD VerifyCatalogSignature(_In_ HANDLE FileHandle,
	_In_ BOOL UseStrongSigPolicy)
{
	DWORD Error = ERROR_SUCCESS;
	BOOL Found = FALSE;
	HCATADMIN CatAdminHandle = NULL;
	HCATINFO CatInfoHandle = NULL;
	DWORD HashLength = 0;
	PBYTE HashData = NULL;
	CERT_STRONG_SIGN_PARA SigningPolicy;

	if (UseStrongSigPolicy != FALSE)
	{
		SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
		SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
		SigningPolicy.pszOID = szOID_CERT_STRONG_SIGN_OS_CURRENT;
		if (!CryptCATAdminAcquireContext2(
			&CatAdminHandle,
			NULL,
			BCRYPT_SHA256_ALGORITHM,
			&SigningPolicy,
			0))
		{
			Error = GetLastError();
			goto Cleanup;
		}
	}
	else
	{
		if (!CryptCATAdminAcquireContext2(
			&CatAdminHandle,
			NULL,
			BCRYPT_SHA256_ALGORITHM,
			NULL,
			0))
		{
			Error = GetLastError();
			goto Cleanup;
		}
	}

	// Get size of hash to be used 
	if (!CryptCATAdminCalcHashFromFileHandle2(
		CatAdminHandle,
		FileHandle,
		&HashLength,
		NULL,
		0))
	{
		Error = GetLastError();
		goto Cleanup;
	}
	//EnterCriticalSection(&mlk_cs);
	HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
	//LeaveCriticalSection(&mlk_cs);
	if (HashData == NULL)
	{
		Error = ERROR_OUTOFMEMORY;
		goto Cleanup;
	}


	// Generate hash for a give file 
	if (!CryptCATAdminCalcHashFromFileHandle2(
		CatAdminHandle,
		FileHandle,
		&HashLength,
		HashData,
		0))
	{
		Error = GetLastError();
		goto Cleanup;
	}


	// Find the first catalog containing this hash 
	CatInfoHandle = NULL;
	CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
		CatAdminHandle,
		HashData,
		HashLength,
		0,
		&CatInfoHandle);


	while (CatInfoHandle != NULL)
	{
		CATALOG_INFO catalogInfo;
		catalogInfo.cbStruct = sizeof(catalogInfo);
		Found = TRUE;

		if (!CryptCATCatalogInfoFromContext(
			CatInfoHandle,
			&catalogInfo,
			0))
		{
			Error = GetLastError();
			break;
		}

		//wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

		// Look for the next catalog containing the file's hash 
		CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
			CatAdminHandle,
			HashData,
			HashLength,
			0,
			&CatInfoHandle);
	}


	if (Found != TRUE)
	{
		//wprintf(L"Hash was not found in any catalogs.\n");
		Error = TRUE;
	}

Cleanup:
	//EnterCriticalSection(&mlk_cs);
	if (CatAdminHandle != NULL)
	{
		if (CatInfoHandle != NULL)
		{
			CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
		}

		CryptCATAdminReleaseContext(CatAdminHandle, 0);
	}


	if (HashData != NULL)
	{
		HeapFree(GetProcessHeap(), 0, HashData);
	}
	//LeaveCriticalSection(&mlk_cs);
	return Error;
}


BOOLEAN VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	/*
	WVTPolicyGUID specifies the policy to apply on the file
	WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

	1) The certificate used to sign the file chains up to a root
	certificate located in the trusted root certificate store. This
	implies that the identity of the publisher has been verified by
	a certification authority.

	2) In cases where user interface is displayed (which this example
	does not do), WinVerifyTrust will check for whether the
	end entity certificate is stored in the trusted publisher store,
	implying that the user trusts content from this publisher.

	3) The end entity certificate has sufficient permission to sign
	code, as indicated by the presence of a code signing EKU or no
	EKU.
	*/

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);
	BOOLEAN result = FALSE;
	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.

		- Trusted publisher without any verification errors.

		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.

		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*//*
		wprintf_s(L"The file \"%s\" is signed and the signature "
			L"was verified.\n",
			pwszSourceFile);*/
		result = TRUE;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			/*wprintf_s(L"The file \"%s\" is not signed.\n",
				pwszSourceFile);*/
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			/*
			wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				pwszSourceFile);*/
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		/*wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");*/
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		wprintf_s(L"The signature is present, but not "
			L"trusted.\n");
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		/*
		wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L"or timestamp errors.\n");*/
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		/*wprintf_s(L"Error is: 0x%x.\n",
			lStatus);*/
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	return result;
}



BOOL __cdecl wrIsSignedCatalog(_In_ unsigned int argc, _In_reads_(argc) PWSTR wargv[])
{
	DWORD Error = ERROR_SUCCESS;
	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	DWORD ArgStart = 1;
	BOOL UseStrongSigPolicy = FALSE;

	if (argc < 3 || argc > 4)
	{
		//PrintUsage(wargv[0]);
		Error = ERROR_INVALID_PARAMETER;
		goto Cleanup;
	}

	if (_wcsicmp(wargv[ArgStart], L"-p") == 0)
	{
		UseStrongSigPolicy = TRUE;
		ArgStart++;
	}

	if (ArgStart + 1 >= argc)
	{
		//PrintUsage(wargv[0]);
		Error = ERROR_INVALID_PARAMETER;
		goto Cleanup;
	}

	if ((wcslen(wargv[ArgStart]) != 2) ||
		((_wcsicmp(wargv[ArgStart], L"-c") != 0) &&
			(_wcsicmp(wargv[ArgStart], L"-e") != 0)))
	{
		//PrintUsage(wargv[0]);
		Error = ERROR_INVALID_PARAMETER;
		goto Cleanup;
	}

	FileHandle = CreateFileW(wargv[ArgStart + 1],
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		Error = GetLastError();
		////PrintError(Error);
		goto Cleanup;
	}

	if (_wcsicmp(wargv[ArgStart], L"-c") == 0)
	{
		Error = VerifyCatalogSignature(FileHandle, UseStrongSigPolicy);

		//printf("%S\n", wargv[ArgStart + 1]);
	}
	else if (_wcsicmp(wargv[ArgStart], L"-e") == 0)
	{
		Error = VerifyEmbeddedSignatures(wargv[ArgStart + 1], FileHandle, UseStrongSigPolicy);

	}
	else
	{
		//PrintUsage(wargv[0]);
		Error = ERROR_INVALID_PARAMETER;
	}

Cleanup:
	if (FileHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(FileHandle);
	}

	return Error;
}


 BOOL __stdcall WrIsSignedExeFile(wchar_t* filename)
{
	wchar_t* wargv[3];
	/////////EnterCriticalSection(&mlk_cs);
	wchar_t sme[BUFSZ];
	wchar_t sdc[BUFSZ];
	ZeroMemory(sme, BUFSZ);
	wcscpy_s(sme, BUFSZ, L"scanUser.exe");

	ZeroMemory(sdc, BUFSZ);
	wcscpy_s(sdc, BUFSZ, L"-c");
	wargv[0] = sme;

	wargv[1] = sdc;

	wargv[2] = filename;


	BOOL isSigned = VerifyEmbeddedSignature(filename);

	if (!isSigned)
	{
		isSigned = !wrIsSignedCatalog(3, wargv);
	}
	//MessageBox(NULL, isSigned?filename:L"No",L"",0);
	return isSigned;
}





__declspec(dllexport)  BOOL __stdcall IsElevated(int prID) {
	BOOL fRet = FALSE;
	HANDLE Hpr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, prID);

	HANDLE hToken = NULL;
	if (OpenProcessToken(Hpr, TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	CloseHandle(Hpr);
	return fRet;
}