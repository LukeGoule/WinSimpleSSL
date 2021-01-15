#pragma once

/*
Utilises WININET to make secure connections to the internet.
We can also get information of certificates from servers using
this library. Neat.
*/

#include <string>
#include <unordered_map>
#include <thread>
#include <vector>
#include <map>

#include <Windows.h>
#include <WinInet.h>
#include <Shlobj.h>

#define ENCODE_FUNCTION(x) x /*set your encryption function here: e.g. _xor_*/
#define _(x) ENCODE_FUNCTION(x)

namespace SimpleSSL
{
	enum RequestType_t
	{
		GET,
		POST,
		HEAD
	};

	BOOL Request_GET(const std::string& server, const std::string& file_url, std::string& destination_buffer);
	BOOL Request_POST(const std::string& server, const std::string& file_url, std::string& destination_buffer, std::unordered_map<std::string, std::string> post_data);

	/*
	Get the hash of the SSL certificate of a server.
	This is useful for making sure the server has not been proxied by an unauthorised party.
	*/
	size_t			CheckSSLCert(const std::string& server);

	/*
	Start an internet session. This can be called any number of time. Effectively wraps InternetOpenA.
	*/
	HINTERNET		CreateInternetSession(std::string UserAgent, DWORD dwFlags = NULL);
	
	/*
	Open a connection to a server (Server).
	Server can be an IP address or a domain name. Domain names are resolved internally.
	Returns NULL on failure.
	*/
	HINTERNET		CreateSSLConnection(HINTERNET hInternetSession, std::string Server, INTERNET_PORT iINetPort = INTERNET_DEFAULT_HTTPS_PORT, std::string szUsername = "", std::string szPassword = "");

	/*
	Start forming a request for the server to handle.
	Returns NULL on fail.
	*/
	HINTERNET		CreateRequest(HINTERNET hServerConnection, RequestType_t Type, LPCSTR RequestedFile, const char* HTTPvers = _("HTTP/1.0"));
	
	/*
	Finalises the generated request and sends it to the server via TLS.
	Returns FALSE on failure (i.e connection interruption).
	*/
	BOOL			SendRequest(HINTERNET hRequest, RequestType_t Type, std::unordered_map<std::string, std::string> PostData = {});

	/*
	Synchronously reads the response from the server into the given buffer, OutputBuffer.
	Returns FALSE on failure (i.e connection interruption).
	*/
	BOOL			ReadResponseToEnd(HINTERNET hRequest, std::string& OutputBuffer);
	
	/*
	Quickly cleanup, returns false if it doesn't cleanup the handles correctly.
	*/
	BOOL			FinaliseSession(HINTERNET hInternetSession, HINTERNET hConnection, HINTERNET hRequest);
	
	/*
	Generates a random string of numbers to be used as the user agent. I recommend not doing this if you want an auth system.
	An idea is to perhaps use something like the hash of a username and IP as the user agent.
	*/
	std::string		RandomUserAgent();
}