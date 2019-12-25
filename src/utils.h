#include <string>
#include <string_view>

namespace cngeant {

std::string format_fingerprint(std::string_view data);
std::string base16(std::string_view data);
std::string base64(std::string_view data);

std::wstring to_utf16(std::string_view data);
std::string to_utf8(std::wstring_view data);
std::string guid4();

template <typename T>
T to_big_endian(T value);

template <typename F>
struct _deferred
{
	_deferred(F && fn)
		: _fn(std::forward<F>(fn))
	{
	}

	~_deferred()
	{
		_fn();
	}

	_deferred(_deferred const &) = delete;
	_deferred & operator=(_deferred const &) = delete;

	std::remove_reference_t<F> _fn;
};

#ifndef PP_CAT
#define PP_CAT2(a, b) a ## b
#define PP_CAT(a, b) PP_CAT2(a, b)
#endif

#define defer ::cngeant::_deferred PP_CAT(_deferred_, __COUNTER__) = [&]() noexcept -> void

}

#pragma once
