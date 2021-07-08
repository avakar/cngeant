#include "utils.h"
#include <system_error>
#include <intrin.h>
#include <windows.h>
#include "win32_utils.h"

namespace cngeant {

void update_user_environment(std::initializer_list<std::pair<std::wstring, std::wstring>> env)
{
	HKEY env_key;
	LRESULT err = RegOpenKeyW(HKEY_CURRENT_USER, L"Environment", &env_key);
	if (err)
		throw std::system_error(err, std::system_category());
	defer{ RegCloseKey(env_key); };

	for (auto && [key, value] : env)
	{
		err = RegSetValueExW(env_key, key.c_str(), 0, REG_SZ, (BYTE const *)value.c_str(), value.size() * 2 + 2);
		if (err)
			throw std::system_error(err, std::system_category());
	}

	if (!SendNotifyMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment"))
		throw std::system_error(::GetLastError(), std::system_category());
}

std::string format_fingerprint(std::string_view data)
{
	char const digits[] = "0123456789abcdef";

	std::string r;
	r.reserve(data.size() * 3);

	for (char ch: data)
	{
		r.push_back(digits[(ch >> 4) & 0xf]);
		r.push_back(digits[ch & 0xf]);
		r.push_back(':');
	}

	r.pop_back();
	return r;
}

std::string base16(std::string_view data)
{
	char const digits[] = "0123456789abcdef";

	std::string r;
	r.reserve(data.size() * 2);

	for (char ch: data)
	{
		r.push_back(digits[(ch >> 4) & 0xf]);
		r.push_back(digits[ch & 0xf]);
	}

	return r;
}

std::string base64(std::string_view data)
{
	char const digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	uint8_t const * p = (uint8_t const *)data.data();
	uint8_t const * last = p + data.size();

	std::string r;
	r.reserve((data.size() * 4 + 2) / 3);

	uint32_t v;
	while (last - p >= 3)
	{
		v = (p[0] << 16) | (p[1] << 8) | p[2];
		r.push_back(digits[(v >> 18) & 0x3f]);
		r.push_back(digits[(v >> 12) & 0x3f]);
		r.push_back(digits[(v >> 6) & 0x3f]);
		r.push_back(digits[v & 0x3f]);

		p += 3;
	}

	switch (last - p)
	{
	case 2:
		v = (p[0] << 16) | (p[1] << 8);
		r.push_back(digits[(v >> 18) & 0x3f]);
		r.push_back(digits[(v >> 12) & 0x3f]);
		r.push_back(digits[(v >> 6) & 0x3f]);
		r.push_back('=');
		break;
	case 1:
		v = (p[0] << 16);
		r.push_back(digits[(v >> 18) & 0x3f]);
		r.push_back(digits[(v >> 12) & 0x3f]);
		r.push_back('=');
		r.push_back('=');
		break;
	}

	return r;
}

std::wstring to_utf16(std::string_view data)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, data.data(), data.size(), nullptr, 0);
	if (len < 0)
		throw std::system_error(GetLastError(), std::system_category());

	std::wstring r;
	r.resize(len + 1);

	len = MultiByteToWideChar(CP_UTF8, 0, data.data(), data.size(), r.data(), r.size());
	if (len < 0)
		throw std::system_error(GetLastError(), std::system_category());

	r.resize(len);
	return r;
}

std::string to_utf8(std::wstring_view data)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, data.data(), data.size(), nullptr, 0, nullptr, nullptr);
	if (len < 0)
		throw std::system_error(GetLastError(), std::system_category());

	std::string r;
	r.resize(len + 1);

	len = WideCharToMultiByte(CP_UTF8, 0, data.data(), data.size(), r.data(), r.size(), nullptr, nullptr);
	if (len < 0)
		throw std::system_error(GetLastError(), std::system_category());

	r.resize(len);
	return r;
}

std::string guid4()
{
	UCHAR key_guid[16];
	bcrypt_try BCryptGenRandom(nullptr, key_guid, sizeof key_guid, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	char const digits[] = "0123456789abcdef";

	std::string r;
	r.resize(36);

	UCHAR const * src = key_guid;
	char * p = r.data();

	auto convert_digit = [&] {
		auto ch = *src++;
		*p++ = digits[(ch >> 4) & 0xf];
		*p++ = digits[ch & 0xf];
	};

	convert_digit();
	convert_digit();
	convert_digit();
	convert_digit();
	*p++ = '-';
	convert_digit();
	convert_digit();
	*p++ = '-';
	convert_digit();
	convert_digit();
	*p++ = '-';
	convert_digit();
	convert_digit();
	*p++ = '-';
	convert_digit();
	convert_digit();
	convert_digit();
	convert_digit();
	convert_digit();
	convert_digit();

	return r;
}

template <>
uint32_t to_big_endian(uint32_t value)
{
	return _byteswap_ulong(value);
}

}
