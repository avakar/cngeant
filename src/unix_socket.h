#include "agent.h"

#include <filesystem>
#include <mutex>
#include <random>
#include <stdint.h>
#include <string_view>
#include <vector>

namespace cngeant {

struct unix_sock_server
{
	unix_sock_server(std::string_view name_in_tmp, agent & ag);
	~unix_sock_server();

private:
	agent & _ag;
	HANDLE _stop_event;

	std::thread _listen_thread;
};

}

#pragma once
