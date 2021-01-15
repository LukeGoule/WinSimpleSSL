# WinSimpleSSL
Organised wrapper for WinINet.dll's SSL functionality.

## Example
```cpp
#include <iostream>

#include "SimpleSSL.hpp"

int main(int argc, char** argv) 
{
	constexpr const char* SERVER = "ergine.cc";
	constexpr const char* GET_BOUNCE_FILE = "/external/74f6c49172ee292d38bb6e6dd42eb9e2/pong.php";
	constexpr const char* POST_BOUNCE_FILE = "/external/74f6c49172ee292d38bb6e6dd42eb9e2/post_pong.php";

	printf("Server Cert Hash: 0x%x\n", SimpleSSL::CheckSSLCert(SERVER));

	// Example of sending a basic GET request.
	std::string GetReturn;
	if (SimpleSSL::Request_GET(SERVER, GET_BOUNCE_FILE, GetReturn))
	{
		std::cout << "Server returned: " << GetReturn << std::endl;
	}
	else
	{
		std::cout << "Failed to send!" << std::endl;
	}

	// Example of sending a basic POST request.
	std::string PostReturn;
	if (SimpleSSL::Request_POST(SERVER, POST_BOUNCE_FILE, PostReturn,
		// This is the post information that is sent to the server.
		// This would be encoded as 'ping=<current time>'
		{ 
			{"ping", std::to_string(time(0))},
		}))
	{
		std::cout << "Server returned: " << PostReturn << std::endl;
	}
	else 
	{
		std::cout << "Failed to send!";
	}

	return 0;
}
```
