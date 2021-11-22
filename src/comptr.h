#include <memory>
#include <utility>
#include <system_error>

#include <windows.h>

template <typename T>
struct com_ptr
{
	com_ptr() noexcept
		: _ptr(nullptr)
	{
	}

	explicit com_ptr(T * ptr) noexcept
		: _ptr(ptr)
	{
	}

	static auto const & iid() noexcept
	{
		return __uuidof(T);
	}

	T * get() const noexcept
	{
		return _ptr;
	}

	explicit operator bool() const noexcept
	{
		return _ptr != nullptr;
	}

	T * operator->() const noexcept
	{
		return _ptr;
	}

	T ** operator~() noexcept
	{
		this->reset();
		return &_ptr;
	}

	void reset(T * ptr = nullptr) noexcept
	{
		if (_ptr)
			_ptr->Release();
		_ptr = ptr;
	}

	~com_ptr()
	{
		this->reset();
	}

	com_ptr(com_ptr const & o) noexcept
		: _ptr(o._ptr)
	{
		if (_ptr)
			_ptr->AddRef();
	}

	com_ptr(com_ptr && o) noexcept
		: _ptr(std::exchange(o._ptr, nullptr))
	{
	}

	com_ptr & operator=(com_ptr o) noexcept
	{
		std:swap(_ptr, o._ptr);
		return *this;
	}

private:
	T * _ptr;
};

template <typename T>
struct task_mem
{
	task_mem() noexcept
		: _ptr(nullptr)
	{
	}

	T * get() const noexcept
	{
		return _ptr;
	}

	T * operator->() const noexcept
	{
		return _ptr;
	}

	T ** operator~() noexcept
	{
		this->reset();
		return &_ptr;
	}

	void reset(T * ptr = nullptr) noexcept
	{
		if (_ptr)
			CoTaskMemFree(_ptr);
		_ptr = ptr;
	}

	~task_mem()
	{
		this->reset();
	}

	task_mem(task_mem && o) noexcept
		: _ptr(std::exchange(o._ptr, nullptr))
	{
	}

	task_mem & operator=(task_mem o) noexcept
	{
		std::swap(_ptr, o._ptr);
		return *this;
	}

private:
	T * _ptr;
};

struct _hresult_checker
{
	HRESULT operator%(HRESULT hr)
	{
		if (FAILED(hr))
			throw std::system_error(hr, std::system_category());
		return hr;
	}
};

#define hrtry ::_hresult_checker{} %

#pragma once
