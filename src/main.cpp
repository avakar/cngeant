#include "agent.h"

#include <windows.h>
#include "resource.h"

#include <system_error>

using namespace cngeant;

static bool memcpy_section(void * dest, void const * src, size_t len)
{
	__try
	{
		memcpy(dest, src, len);
	}
	__except (GetExceptionCode() == STATUS_IN_PAGE_ERROR)
	{
		return false;
	}

	return true;
}

static void copy_to_clipboard(std::string_view str, HWND owner)
{
	HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, str.size() + 1);
	if (!mem)
		throw std::bad_alloc();
	defer{ if (mem) GlobalFree(mem); };

	char * p = (char *)GlobalLock(mem);
	if (!p)
		throw std::bad_alloc();

	memcpy(p, str.data(), str.size());
	p[str.size()] = 0;
	GlobalUnlock(p);

	if (!OpenClipboard(owner))
		throw std::system_error(GetLastError(), std::system_category());
	defer{ CloseClipboard(); };

	if (!EmptyClipboard())
		throw std::system_error(GetLastError(), std::system_category());

	if (!SetClipboardData(CF_TEXT, mem))
		throw std::system_error(GetLastError(), std::system_category());

	mem = 0;
}

static std::wstring _get_default_key_name()
{
	DWORD size = 0;
	if (!GetComputerNameExW(ComputerNameDnsFullyQualified, nullptr, &size))
	{
		DWORD err = GetLastError();
		if (err != ERROR_MORE_DATA)
			throw std::system_error(err, std::system_category());
	}

	std::wstring computer_name;
	computer_name.resize(++size);
	if (!GetComputerNameExW(ComputerNameDnsFullyQualified, computer_name.data(), &size))
		throw std::system_error(GetLastError(), std::system_category());
	computer_name.resize(size);

	size = 0;
	if (!GetUserNameW(nullptr, &size))
	{
		DWORD err = GetLastError();
		if (err != ERROR_INSUFFICIENT_BUFFER)
			throw std::system_error(err, std::system_category());
	}

	std::wstring username;
	username.resize(++size);
	if (!GetUserNameW(username.data(), &size))
		throw std::system_error(GetLastError(), std::system_category());
	username.resize(size - 1);

	return username + L"@" + computer_name;
}

static INT_PTR input_box_dlgproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		auto ag = (agent *)lparam;
		SetWindowLongPtrW(hwnd, DWLP_USER, lparam);

		SetDlgItemTextW(hwnd, IDC_NAME_EDIT, _get_default_key_name().c_str());
		for (auto && name: ag->new_key_types())
			SendDlgItemMessageW(hwnd, IDC_TYPE_COMBO, CB_ADDSTRING, 0, (LPARAM)to_utf16(name).c_str());
		SendDlgItemMessageW(hwnd, IDC_TYPE_COMBO, CB_SETCURSEL, 0, 0);

		return TRUE;
	}
	case WM_CLOSE:
		EndDialog(hwnd, 0);
		return TRUE;
	case WM_COMMAND:
		if (lparam && HIWORD(wparam) == BN_CLICKED && LOWORD(wparam) == IDOK)
		{
			auto ag = (agent *)GetWindowLongPtrW(hwnd, DWLP_USER);

			std::wstring name;
			name.resize(MAX_PATH);
			name.resize(GetDlgItemTextW(hwnd, IDC_NAME_EDIT, name.data(), name.size()));

			auto id = SendDlgItemMessageW(hwnd, IDC_TYPE_COMBO, CB_GETCURSEL, 0, 0);
			ag->new_key(id, to_utf8(name));

			EndDialog(hwnd, IDOK);
			return TRUE;
		}

		if (lparam && HIWORD(wparam) == BN_CLICKED && LOWORD(wparam) == IDCANCEL)
		{
			EndDialog(hwnd, IDCANCEL);
			return TRUE;
		}
		break;
	}

	return FALSE;
}

static bool _has_run_entry(wchar_t const * entry_name)
{
	HKEY key;
	win32_try RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_QUERY_VALUE, &key);
	defer{ RegCloseKey(key); };

	auto err = RegQueryValueExW(key, entry_name, 0, nullptr, nullptr, nullptr);
	if (err == ERROR_SUCCESS)
		return true;
	if (err == ERROR_FILE_NOT_FOUND)
		return false;
	throw std::system_error(err, std::system_category());
}

static void _clear_run_entry(wchar_t const * entry_name)
{
	HKEY key;
	win32_try RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
	defer{ RegCloseKey(key); };

	auto err = RegDeleteValueW(key, entry_name);
	if (err != ERROR_SUCCESS && err != ERROR_FILE_NOT_FOUND)
		throw std::system_error(err, std::system_category());
}

static void _set_run_entry(wchar_t const * entry_name)
{
	WCHAR exe_file_name[MAX_PATH + 1];
	if (!GetModuleFileNameW(nullptr, exe_file_name, std::size(exe_file_name) - 1))
		throw std::system_error(GetLastError(), std::system_category());
	exe_file_name[MAX_PATH] = 0;

	HKEY key;
	win32_try RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
	defer{ RegCloseKey(key); };

	win32_try RegSetValueExW(key, entry_name, 0, REG_SZ, (BYTE const *)exe_file_name, wcslen(exe_file_name) * 2 + 2);
}

static LRESULT CALLBACK main_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	if (msg == WM_CREATE)
	{
		CREATESTRUCT * cs = (CREATESTRUCT *)lparam;
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
		return 0;
	}

	auto ag = (agent *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

	if (msg == WM_COPYDATA)
	{
		auto cds = (COPYDATASTRUCT const *)lparam;
		if (cds->dwData != 0x804e50ba || cds->cbData == 0)
			return FALSE;

		auto data = (char const *)cds->lpData;
		if (std::find(data, data + cds->cbData, 0) != data + cds->cbData - 1)
			return FALSE;

		win32_handle hsection{ OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, data) };
		if (!hsection)
			throw std::system_error(GetLastError(), std::system_category());
		win32_mapped_view view_ptr{ MapViewOfFile(hsection.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) };
		if (!view_ptr)
			throw std::system_error(GetLastError(), std::system_category());

		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery(view_ptr.get(), &mbi, sizeof mbi))
			throw std::system_error(GetLastError(), std::system_category());

		size_t view_size = mbi.RegionSize;
		if (view_size < 4)
			return FALSE;

		uint32_t msg_size;
		memcpy_section(&msg_size, view_ptr.get(), 4);
		msg_size = _byteswap_ulong(msg_size);

		char msg[0x1000];
		if (msg_size > sizeof msg || view_size - 4 < msg_size)
			return FALSE;

		memcpy_section(msg, (char const *)view_ptr.get() + 4, msg_size);

		mapped_view_ssh_writer wr((char *)view_ptr.get(), view_size);

		if (!ag->process_message(wr, { msg, msg_size }))
			return FALSE;

		wr.end_object();
		return TRUE;
	}

	if (msg == WM_USER + 1)
	{
		if (LOWORD(lparam) == WM_CONTEXTMENU)
		{
			HMENU menu = CreatePopupMenu();
			defer{ DestroyMenu(menu); };

			AppendMenuW(menu, MF_STRING | MF_ENABLED, 2, L"Generate new key pair");

			auto const & keys = ag->keys();
			if (!keys.empty())
			{
				AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

				UINT_PTR id = 0x100;
				for (key_info const & key : keys)
				{
					std::string key_label = key.comment;
					key_label.append(" (");
					key_label.append(key.algo_id);
					
					if (key.is_hw)
						key_label.append("-tpm");
					key_label.append(")");

					HMENU submenu = CreatePopupMenu();
					if (!AppendMenuW(menu, MF_STRING | MF_ENABLED | MF_POPUP, (UINT_PTR)submenu, to_utf16(key_label).c_str()))
					{
						DestroyMenu(submenu);
						return FALSE;
					}

					AppendMenuW(submenu, MF_STRING | MF_ENABLED, id, L"Copy to clipboard");
					AppendMenuW(submenu, MF_SEPARATOR, 0, nullptr);
					AppendMenuW(submenu, MF_STRING | MF_ENABLED, 0x4000 | id, L"Delete key...");
					++id;
				}
			}

			AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

			bool has_run_entry = _has_run_entry(L"cngeant");

			AppendMenuW(menu, MF_STRING | MF_ENABLED | (has_run_entry? MF_CHECKED: 0), 3, L"Run on startup");
			AppendMenuW(menu, MF_STRING | MF_ENABLED, 1, L"Quit");

			SetForegroundWindow(hwnd);
			int r = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, LOWORD(wparam), HIWORD(wparam), 0, hwnd, nullptr);
			PostMessageW(hwnd, WM_NULL, 0, 0);

			if (r >= 0x4100)
			{
				key_info const & key = keys[r - 0x4100];
				if (MessageBoxW(hwnd, L"The key will be deleted. This operation cannot be done. Are you sure?", L"Delete key", MB_ICONQUESTION | MB_YESNO) == IDYES)
					ag->delete_key(r - 0x4100);
			}
			else if (r >= 0x100)
			{
				key_info const & key = keys[r - 0x100];
				copy_to_clipboard(key.get_public_key(), hwnd);
			}
			else if (r == 3)
			{
				if (has_run_entry)
					_clear_run_entry(L"cngeant");
				else
					_set_run_entry(L"cngeant");
			}
			else if (r == 2)
			{
				HINSTANCE hinstance = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
				DialogBoxParamW(hinstance, MAKEINTRESOURCEW(IDD_NEW_KEY), hwnd, &input_box_dlgproc, (LPARAM)ag);
			}
			else if (r == 1)
			{
				PostQuitMessage(0);
			}
		}

		return TRUE;
	}

	return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE hinstance, HINSTANCE, LPWSTR, int)
{
	try
	{
		if (FindWindowW(L"Pageant", L"Pageant"))
			throw std::runtime_error("A Pageant-like service is already running.");

		agent ag;

		WNDCLASSEXW wce = { sizeof wce };
		wce.lpfnWndProc = &main_wnd_proc;
		wce.hInstance = hinstance;
		wce.lpszClassName = L"Pageant";
		auto cls = RegisterClassExW(&wce);
		if (!cls)
			throw std::system_error(GetLastError(), std::system_category());
		defer{ UnregisterClassW((LPCWSTR)cls, hinstance); };

		HWND hwnd = CreateWindowExW(0, L"Pageant", L"Pageant", WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
			CW_USEDEFAULT, HWND_MESSAGE, nullptr, hinstance, &ag);
		if (!hwnd)
			throw std::system_error(GetLastError(), std::system_category());
		defer{ DestroyWindow(hwnd); };

		NOTIFYICONDATAW nid = { sizeof nid };
		nid.hWnd = hwnd;
		nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP | NIF_ICON;
		nid.uCallbackMessage = WM_USER + 1;
		nid.uID = 1;
		nid.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_APPLICATION));
		nid.uVersion = NOTIFYICON_VERSION_4;
		wcscpy(nid.szTip, L"cngeant");

		if (!Shell_NotifyIconW(NIM_ADD, &nid))
			throw std::system_error(GetLastError(), std::system_category());

		if (!Shell_NotifyIconW(NIM_SETVERSION, &nid))
			throw std::system_error(GetLastError(), std::system_category());

		MSG msg;
		for (;;)
		{
			auto r = GetMessageW(&msg, nullptr, 0, 0);
			if (r == -1)
				throw std::system_error(GetLastError(), std::system_category());

			if (r == 0)
				break;

			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}

		Shell_NotifyIconW(NIM_DELETE, &nid);

		return msg.wParam;
	}
	catch (std::exception const & e)
	{
		MessageBoxA(nullptr, e.what(), "Error", MB_ICONERROR | MB_OK);
		return 1;
	}
	catch (...)
	{
		MessageBoxW(nullptr, L"Unknown error", L"Error", MB_ICONERROR | MB_OK);
		return 1;
	}
}
