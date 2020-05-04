#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include "cygwin_socket.h"

namespace cngeant {

cygwin_sock_server::cygwin_sock_server(std::wstring_view name_in_tmp, agent & ag)
	: _ag(ag), _cookie_file(INVALID_HANDLE_VALUE), _stop_event(0)
{
	HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!stop_event)
		throw std::system_error(::GetLastError(), std::system_category());
	defer{
		if (stop_event)
			CloseHandle(stop_event);
	};

	std::uniform_int_distribution<uint32_t> dist;

	uint32_t conn_secret[] = {
		dist(std::default_random_engine()),
		dist(std::default_random_engine()),
		dist(std::default_random_engine()),
		dist(std::default_random_engine()),
	};

	wchar_t tmp_path[MAX_PATH + 1];
	if (!GetTempPathW(std::size(tmp_path), tmp_path))
		throw std::system_error(::GetLastError(), std::system_category());

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!sock)
		throw std::system_error(::GetLastError(), std::system_category());
	defer {
		if (sock != 0)
			closesocket(sock);
	};

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0x0100007f;
	addr.sin_port = 0;
	bind(sock, (sockaddr const *)&addr, sizeof addr);

	listen(sock, SOMAXCONN);

	int namelen = sizeof addr;
	getsockname(sock, (sockaddr *)&addr, &namelen);

	std::filesystem::path fpath = tmp_path;
	fpath /= name_in_tmp;

	HANDLE cookie_file = INVALID_HANDLE_VALUE;
	defer {
		if (cookie_file != INVALID_HANDLE_VALUE)
			CloseHandle(cookie_file);
	};

	{
		char sock_fcontent[64];
		int sock_content_len = sprintf(sock_fcontent, "!<socket >%d s %08X-%08X-%08X-%08X",
			htons(addr.sin_port),
			conn_secret[0],
			conn_secret[1],
			conn_secret[2],
			conn_secret[3]);
		sock_fcontent[sock_content_len++] = 0;

		cookie_file = CreateFileW(fpath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, nullptr);
		if (cookie_file == INVALID_HANDLE_VALUE)
			throw std::system_error(::GetLastError(), std::system_category());

		DWORD written;
		WriteFile(cookie_file, sock_fcontent, sock_content_len, &written, nullptr);
	}

	update_user_environment({
		{ L"SSH_AUTH_SOCK", fpath.native() },
		{ L"SSH_AGENT_PID", std::to_wstring(GetCurrentProcessId()) },
		});

	_listen_thread = std::thread([=] {
		HANDLE hAcceptComplete = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!hAcceptComplete)
			throw std::system_error(::GetLastError(), std::system_category());
		defer{ CloseHandle(hAcceptComplete); };

		for (;;)
		{
			SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (!s)
				throw std::system_error(GetLastError(), std::system_category());
			defer{
				if (s != 0)
					closesocket(s);
			};

			alignas(sockaddr_in) char accept_buf[sizeof(sockaddr_in)*2 + 32];

			DWORD received;
			OVERLAPPED ov = {};
			ov.hEvent = hAcceptComplete;
			if (!AcceptEx(sock, s, accept_buf, 0, sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16, &received, &ov))
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
					uint32_t conn_cookie[4];
					recv_all(conn_cookie);
					if (memcmp(conn_cookie, conn_secret, sizeof conn_cookie) != 0)
						return;

					send(s, (char *)&conn_cookie, sizeof conn_cookie, 0);

					int32_t cred[3];
					recv_all(cred);
					send(s, (char *)&cred, sizeof cred, 0);

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
	std::swap(_cookie_file, cookie_file);
}

cygwin_sock_server::~cygwin_sock_server()
{
	SetEvent(_stop_event);
	_listen_thread.join();
	CloseHandle(_cookie_file);
}

}