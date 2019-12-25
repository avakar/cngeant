#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <memory>

namespace cngeant {

struct win32_handle_deleter
{
	void operator()(HANDLE h) const;
};

struct win32_mapped_view_deleter
{
	void operator()(void * p) const;
};

struct bcrypt_algo_deleter
{
	void operator()(BCRYPT_ALG_HANDLE h) const;
};

using win32_handle = std::unique_ptr<void, win32_handle_deleter>;
using win32_mapped_view = std::unique_ptr<void, win32_mapped_view_deleter>;
using bcrypt_algo_handle = std::unique_ptr<void, bcrypt_algo_deleter>;

struct ncrypt_handle
{
	ncrypt_handle() noexcept;
	explicit ncrypt_handle(NCRYPT_HANDLE h) noexcept;
	ncrypt_handle(ncrypt_handle && o) noexcept;
	~ncrypt_handle();
	ncrypt_handle & operator=(ncrypt_handle && o) noexcept;

	NCRYPT_HANDLE get() const noexcept;
	void reset(NCRYPT_HANDLE h = 0) noexcept;
	NCRYPT_HANDLE release() noexcept;
	NCRYPT_HANDLE * operator~() noexcept;

private:
	NCRYPT_HANDLE _h;
};

struct ntstatus_checker
{
	void operator%(NTSTATUS status) const;
};

#define win32_try ::cngeant::ntstatus_checker{} %
#define ncrypt_try ::cngeant::ntstatus_checker{} %
#define bcrypt_try ::cngeant::ntstatus_checker{} %

}

#pragma once
