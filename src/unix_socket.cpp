#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <afunix.h>
#include "unix_socket.h"

namespace cngeant {

unix_sock_server::unix_sock_server(std::string_view name_in_tmp, agent & ag)
	: _ag(ag), _stop_event(0)
{
	HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!stop_event)
		throw std::system_error(::GetLastError(), std::system_category());
	defer{
		if (stop_event)
			CloseHandle(stop_event);
	};

	wchar_t tmp_path[MAX_PATH + 1];
	if (!GetTempPathW(std::size(tmp_path), tmp_path))
		throw std::system_error(::GetLastError(), std::system_category());

	std::string npath = std::filesystem::path(tmp_path).string();
	npath.append(name_in_tmp);

	if (npath.size() >= sizeof(sockaddr_un::sun_path))
		throw std::runtime_error("Path to unix socket is too long");

	SOCKET sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!sock)
		throw std::system_error(::GetLastError(), std::system_category());
	defer {
		if (sock != 0)
			closesocket(sock);
	};

	(void)DeleteFileA(npath.c_str());

	sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, npath.c_str());
	if (bind(sock, (sockaddr const *)&addr, sizeof addr) < 0)
		throw std::system_error(::GetLastError(), std::system_category());

	if (listen(sock, SOMAXCONN) < 0)
		throw std::system_error(::GetLastError(), std::system_category());

	_listen_thread = std::thread([=] {
		HANDLE hAcceptComplete = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!hAcceptComplete)
			throw std::system_error(::GetLastError(), std::system_category());
		defer{ CloseHandle(hAcceptComplete); };

		for (;;)
		{
			SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
			if (!s)
				throw std::system_error(GetLastError(), std::system_category());
			defer{
				if (s != 0)
					closesocket(s);
			};

			alignas(sockaddr_un) char accept_buf[sizeof(sockaddr_un)*2 + 32];

			DWORD received;
			OVERLAPPED ov = {};
			ov.hEvent = hAcceptComplete;
			if (!AcceptEx(sock, s, accept_buf, 0, sizeof(sockaddr_un) + 16, sizeof(sockaddr_un) + 16, &received, &ov))
			{
				DWORD err = GetLastError();
				if (err != ERROR_IO_PENDING)
					throw std::system_error(err, std::system_category());

				HANDLE h[2] = { hAcceptComplete, stop_event };
				switch (WaitForMultipleObjects(2, h, FALSE, INFINITE))
				{
				case WAIT_OBJECT_0:
					break;
				case WAIT_OBJECT_0 + 1:
					return;
				default:
					throw std::system_error(::GetLastError(), std::system_category());
				}
			}

			std::thread thr([=] {
				defer{ closesocket(s); };

				auto recv_buf = [s](char * buf, size_t size) {
					while (size)
					{
						int r = recv(s, buf, size, 0);
						if (r < 0)
							throw std::runtime_error("err");

						if (r == 0)
							throw std::runtime_error("eof");

						buf += r;
						size -= r;
					}
				};

				auto recv_all = [s, recv_buf](auto & v) {
					char * buf = (char *)&v;
					size_t size = sizeof v;
					recv_buf(buf, size);
				};

				try
				{
					std::vector<char> cmd_buf;

					for (;;)
					{
						uint32_t cmd_len;
						recv_all(cmd_len);
						cmd_len = _byteswap_ulong(cmd_len);
						cmd_buf.resize(cmd_len);

						recv_buf(cmd_buf.data(), cmd_buf.size());

						string_ssh_writer wr;
						if (!_ag.process_message(wr, { cmd_buf.data(), cmd_buf.size() }))
							break;

						std::string reply = std::move(wr).str();
						cmd_len = _byteswap_ulong(reply.size());

						send(s, (char *)&cmd_len, sizeof cmd_len, 0);
						send(s, reply.data(), reply.size(), 0);
					}
				}
				catch (...)
				{
				}

				closesocket(s);
			});

			s = 0;
			thr.detach();
		}
	});

	sock = 0;
	std::swap(_stop_event, stop_event);
}

unix_sock_server::~unix_sock_server()
{
	SetEvent(_stop_event);
	_listen_thread.join();
}

}