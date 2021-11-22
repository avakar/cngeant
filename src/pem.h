#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct pem_object
{
	std::string label;
	std::vector<std::uint8_t> data;
};

std::vector<pem_object> parse_pem(std::string_view data);

#include <concepts>
#include <stdexcept>
#include <utility>

struct asn1parser
{
	asn1parser(std::span<std::uint8_t const> data)
		: _p(data.data()), _last(_p + data.size())
	{
	}

	asn1parser(asn1parser && o) noexcept
		: _p(std::exchange(o._p, nullptr)), _last(std::exchange(o._last, nullptr))
	{
	}

	~asn1parser() noexcept(false)
	{
		if (std::uncaught_exceptions() == 0)
			this->done();
	}

	asn1parser & operator=(asn1parser o)
	{
		std::swap(_p, o._p);
		std::swap(_last, o._last);
		return *this;
	}

	void discard()
	{
		_p = _last = nullptr;
	}

	void done()
	{
		if (_p != _last)
			throw std::runtime_error("trailing data");
	}

	asn1parser open_structure()
	{
		return this->_eat_tag(0x30);
	}

	template <typename T>
	T read_int()
	{
		auto cont = this->read_bigint();
		if (!cont.empty() && (cont[0] & 0x80))
			throw std::out_of_range();

		if (cont.size() > sizeof(T))
			throw std::runtime_error("unsupported int");

		T r = 0;
		for (auto x: cont)
			r = (r << 8) | x;
		return r;
	}

	template <std::signed_integral T>
	T read_int()
	{
		auto cont = this->read_bigint();

		T r = 0;
		std::uint8_t prefix = 0;
		if (!cont.empty() && (cont[0] & 0x80))
		{
			r = -1;
			prefix = 0xff;
		}

		if (cont.size() > sizeof(T))
			throw std::runtime_error("unsupported int");

		for (auto x: cont)
			r = (r << 8) | x;
		return r;
	}

	std::span<std::uint8_t const> read_tag(std::uint8_t tag)
	{
		return this->_eat_tag(tag);
	}

	std::span<std::uint8_t const> read_big_uint()
	{
		auto r = this->read_bigint();
		if (r[0] & 0x80)
			throw std::runtime_error("negative uint");
		while (!r.empty() && r[0] == 0)
			r = r.subspan(1);
		return r;
	}

	std::span<std::uint8_t const> read_bigint()
	{
		auto r = this->_eat_tag(0x02);
		if (r.empty())
			throw std::runtime_error("empty int");

		if (r.size() >= 2 && (
			(r[0] == 0 && (r[1] & 0x80) == 0)
			|| (r[0] == 0xff && (r[1] & 0x80) != 0)))
		{
			throw std::runtime_error("not in der");
		}

		return r;
	}

private:
	std::span<std::uint8_t const> _eat_tag(std::uint8_t tag)
	{
		if (_p == _last || *_p++ != tag || _p == _last)
			throw std::runtime_error("unexpected");

		std::size_t l = *_p++;
		if (l & 0x80)
		{
			l &= 0x7f;
			if (l == 0)
				throw std::runtime_error("not allowed in der");
			if (l == 0x7f)
				throw std::runtime_error("reserved length");

			if (l > sizeof(std::size_t) || l > _last - _p)
				throw std::runtime_error("invalid length");

			std::size_t len = 0;
			for (std::size_t i = 0; i != l; ++i)
				len = (len << 8) | *_p++;

			l = len;
		}

		if (l > _p - _last)
			throw std::runtime_error("overlong");

		std::span<std::uint8_t const> r{ _p, l };
		_p += l;
		return r;
	}

	std::uint8_t const * _p;
	std::uint8_t const * _last;
};

#pragma once
