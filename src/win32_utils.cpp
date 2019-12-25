#include "win32_utils.h"
#include <system_error>

namespace cngeant {

void win32_handle_deleter::operator()(HANDLE h) const
{
	CloseHandle(h);
}

void win32_mapped_view_deleter::operator()(void * p) const
{
	UnmapViewOfFile(p);
}

void bcrypt_algo_deleter::operator()(BCRYPT_ALG_HANDLE h) const
{
	BCryptCloseAlgorithmProvider(h, 0);
}

void ntstatus_checker::operator%(NTSTATUS status) const
{
	if (FAILED(status))
		throw std::system_error(status, std::system_category());
}

ncrypt_handle::ncrypt_handle() noexcept
	: _h(0)
{
}

ncrypt_handle::ncrypt_handle(NCRYPT_HANDLE h) noexcept
	: _h(h)
{
}

ncrypt_handle::ncrypt_handle(ncrypt_handle && o) noexcept
	: _h(o._h)
{
	o._h = 0;
}

ncrypt_handle::~ncrypt_handle()
{
	this->reset();
}

ncrypt_handle & ncrypt_handle::operator=(ncrypt_handle && o) noexcept
{
	std::swap(_h, o._h);
	return *this;
}

NCRYPT_HANDLE ncrypt_handle::get() const noexcept
{
	return _h;
}

void ncrypt_handle::reset(NCRYPT_HANDLE h) noexcept
{
	if (_h)
		NCryptFreeObject(_h);
	_h = h;
}

NCRYPT_HANDLE ncrypt_handle::release() noexcept
{
	return _h;
}

NCRYPT_HANDLE * ncrypt_handle::operator~() noexcept
{
	this->reset();
	return &_h;
}

}
