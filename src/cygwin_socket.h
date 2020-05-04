#include "agent.h"

#include <filesystem>
#include <mutex>
#include <random>
#include <stdint.h>
#include <string_view>
#include <vector>

namespace cngeant {

struct cygwin_sock_server
{
	cygwin_sock_server(std::wstring_view name_in_tmp, agent & ag);
	~cygwin_sock_server();

private:
	agent & _ag;
	HANDLE _cookie_file;
	HANDLE _stop_event;

	std::thread _listen_thread;
};

}

#pragma once
