#include "SimpleSSL.hpp"

#pragma comment (lib, "wininet")

HINTERNET SimpleSSL::CreateInternetSession(std::string UserAgent, DWORD dwFlags)
{
	HINTERNET hNewInternetSession = InternetOpenA(UserAgent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, dwFlags);

	if (!hNewInternetSession)
	{
		/* TODO: Log something nice here */
		return NULL;
	}
	else {
		return hNewInternetSession;
	}
}

HINTERNET SimpleSSL::CreateSSLConnection(HINTERNET hInternetSession, std::string server, INTERNET_PORT iINetPort, std::string szUsername, std::string szPassword)
{
	HINTERNET hServerConnection = 
		InternetConnectA(
			hInternetSession,				// Handle to a previously opened internet session
			(LPCSTR)server.c_str(),			// Server (i.e. 127.0.0.1 or google.com)
			iINetPort,						// Port
			(LPCSTR)szUsername.c_str(),		// Username
			(LPCSTR)szPassword.c_str(),		// Password
			INTERNET_SERVICE_HTTP,			// Service Type
			NULL,							// Flags
			NULL							// Context
		);

	if (!hServerConnection)
	{
		/* TODO: Log something nice here */
		return NULL;
	}
	else 
	{
		return hServerConnection;
	}
}

HINTERNET SimpleSSL::CreateRequest(HINTERNET hServerConnection, SimpleSSL::RequestType_t Type, LPCSTR RequestedFile, const char* HTTPvers)
{
	PCTSTR rgpszAcceptTypes[] = { _("text/*"), NULL };

	std::string RequestTypeString;

	switch (Type) {
	case GET:
		RequestTypeString = _("GET");
		break;
	case POST:
		RequestTypeString = _("POST");
		break;
	case HEAD:
		RequestTypeString = _("HEAD");
		break;
	default:
		return NULL;
	}

	HINTERNET hRequest = 
		HttpOpenRequestA(
			hServerConnection, 
			RequestTypeString.c_str(), 
			RequestedFile, 
			HTTPvers, NULL, 
			rgpszAcceptTypes,
			INTERNET_FLAG_SECURE |
			INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
			INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
			INTERNET_FLAG_KEEP_CONNECTION |
			INTERNET_FLAG_NO_COOKIES |
			INTERNET_FLAG_PRAGMA_NOCACHE |
			INTERNET_FLAG_RELOAD,
			NULL);

	if (!hRequest)
	{
		/* TODO: Log something nice here */
		return NULL;
	}
	else
	{
		return hRequest;
	}
}

BOOL SimpleSSL::SendRequest(HINTERNET hRequest, SimpleSSL::RequestType_t Type, std::unordered_map<std::string, std::string> PostData)
{
	BOOL bResult;
	std::string GeneratedPostData = "";
	int FieldCounter = 0;

	// https://stackoverflow.com/a/14551219
	std::string PostRequiredHeader = _("Content-Type: application/x-www-form-urlencoded");

	switch (Type)
	{
	case SimpleSSL::RequestType_t::GET:
	case SimpleSSL::RequestType_t::HEAD:
		bResult = HttpSendRequestA(hRequest, NULL, NULL, NULL, NULL);

		if (bResult == FALSE)
		{
			return false;
		}

		break;

	case SimpleSSL::RequestType_t::POST:
		for (auto Field : PostData)
		{
			GeneratedPostData += Field.first + "=" + Field.second + (FieldCounter == PostData.size() - 1 ? "" : "&");

			FieldCounter += 1;
		}

		bResult = HttpSendRequestA(hRequest, PostRequiredHeader.c_str(), PostRequiredHeader.size(), (LPVOID)(GeneratedPostData.c_str()), GeneratedPostData.size());

		break;

	default:
		/* Error code needed here, something internally has gone wrong */
		return false;
	}

	return bResult;
}

BOOL SimpleSSL::ReadResponseToEnd(HINTERNET hRequest, std::string& OutputBuffer)
{
	const int bufferSize = 256;
	char buff[bufferSize] = {};

	BOOL bDataLeft = TRUE;
	DWORD dwBytesRead = -1;

	while (bDataLeft && dwBytesRead != 0)
	{
		bDataLeft = InternetReadFile(hRequest, buff, bufferSize, &dwBytesRead);

		if (!bDataLeft)
		{
			return FALSE;
		}

		OutputBuffer.append(buff, dwBytesRead);
	}

	return TRUE;
}

BOOL SimpleSSL::FinaliseSession(HINTERNET hInternetSession, HINTERNET hConnection, HINTERNET hRequest)
{
	return InternetCloseHandle(hRequest) && InternetCloseHandle(hConnection) && InternetCloseHandle(hInternetSession);
}

std::string SimpleSSL::RandomUserAgent()
{
	return std::to_string(rand() % 0x90);
}

BOOL SimpleSSL::Request_GET(const std::string& Server, const std::string& FileURL, std::string& OutputBuffer)
{
	HINTERNET hInternetSession;
	HINTERNET hConnection;
	HINTERNET hRequest;
	BOOL bResult;

	hInternetSession = SimpleSSL::CreateInternetSession(RandomUserAgent().c_str());

	if (hInternetSession == 0)
	{
		return FALSE;
	}

	hConnection = SimpleSSL::CreateSSLConnection(hInternetSession, Server.c_str());

	if (hConnection == 0)
	{
		return FALSE;
	}

	hRequest = SimpleSSL::CreateRequest(hConnection, GET, FileURL.c_str());

	if (hRequest == 0)
	{
		return FALSE;
	}

	bResult = SimpleSSL::SendRequest(hRequest, GET);

	if (!SimpleSSL::ReadResponseToEnd(hRequest, OutputBuffer))
	{
		return FALSE;
	}

	SimpleSSL::FinaliseSession(hInternetSession, hConnection, hRequest);

	return TRUE;
}

BOOL SimpleSSL::Request_POST(const std::string& Server, const std::string& FileURL, std::string& OutputBuffer, std::unordered_map<std::string, std::string> PostData) 
{
	HINTERNET hInternetSession;
	HINTERNET hConnection;
	HINTERNET hRequest;
	BOOL bResult;

	hInternetSession = SimpleSSL::CreateInternetSession(RandomUserAgent());

	if (hInternetSession == 0)
	{
		return FALSE;
	}

	hConnection = SimpleSSL::CreateSSLConnection(hInternetSession, Server);

	if (hConnection == 0)
	{
		return FALSE;
	}

	hRequest = SimpleSSL::CreateRequest(hConnection, POST, FileURL.c_str());

	if (hRequest == 0)
	{
		return FALSE;
	}

	bResult = SimpleSSL::SendRequest(hRequest, POST, PostData);

	if (bResult == FALSE)
	{
		return FALSE;
	}

	if (!SimpleSSL::ReadResponseToEnd(hRequest, OutputBuffer))
	{
		return FALSE;
	}

	SimpleSSL::FinaliseSession(hInternetSession, hConnection, hRequest);

	return TRUE;

}

size_t SimpleSSL::CheckSSLCert(const std::string& Server)
{
	HINTERNET hInternetSession;
	HINTERNET hConnection;
	HINTERNET hRequest;
	BOOL bResult;

	hInternetSession = CreateInternetSession(RandomUserAgent());

	if (hInternetSession == 0)
	{
		return 0;
	}

	hConnection = CreateSSLConnection(hInternetSession, Server);

	if (hConnection == 0)
	{
		return 0;
	}

	hRequest = CreateRequest(hConnection, HEAD, NULL);

	if (hRequest == 0)
	{
		return 0;
	}

	bResult = SendRequest(hRequest, HEAD);

	if (!bResult)
	{
		return 0;
	}

	char cert_info_string[2048];
	cert_info_string[0] = '\0';
	DWORD cert_info_length = 2048;
	std::string cert_info_to_hash = "";

	if (InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_CERTIFICATE, &cert_info_string, &cert_info_length))
	{
		INTERNET_CERTIFICATE_INFO cert_info = {};
		cert_info_length = sizeof(INTERNET_CERTIFICATE_INFO);

		if (InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &cert_info, &cert_info_length))
		{
			if (cert_info.lpszEncryptionAlgName)
			{
				std::string alg_name = cert_info.lpszEncryptionAlgName;
				cert_info_to_hash += alg_name;
				LocalFree(cert_info.lpszEncryptionAlgName);
			}

			if (cert_info.lpszIssuerInfo)
			{
				std::string issuer_info = cert_info.lpszIssuerInfo;
				cert_info_to_hash += issuer_info;
				LocalFree(cert_info.lpszIssuerInfo);
			}

			if (cert_info.lpszProtocolName)
			{
				std::string protocol_name = cert_info.lpszProtocolName;
				cert_info_to_hash += protocol_name;
				LocalFree(cert_info.lpszProtocolName);
			}

			if (cert_info.lpszSubjectInfo)
			{
				std::string subject_info = cert_info.lpszSubjectInfo;
				cert_info_to_hash += subject_info;
				LocalFree(cert_info.lpszSubjectInfo);
			}
		}
	}

	auto hash = std::hash<std::string>()(cert_info_to_hash);

	SimpleSSL::FinaliseSession(hInternetSession, hConnection, hRequest);

	return hash;
}