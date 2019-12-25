#include "ssh_pack.h"
#include "utils.h"
#include <windows.h>
#include <stdexcept>
#include <string.h>
#include <utility>

namespace cngeant {

void string_ssh_writer::begin_object()
{
	_str.append((char const *)&_current_object, 4);
	_current_object = _str.size();
}

void string_ssh_writer::append_data(std::string_view data)
{
	_str.append(data);
}

void string_ssh_writer::end_object()
{
	uint32_t object_size = _str.size() - _current_object;
	uint32_t object_size_be = to_big_endian(object_size);

	uint32_t next_object;
	memcpy(&next_object, _str.data() + _current_object - 4, 4);
	memcpy(_str.data() + _current_object - 4, &object_size_be, sizeof object_size_be);
	_current_object = next_object;
}

std::string string_ssh_writer::str() &&
{
	return std::move(_str);
}

mapped_view_ssh_writer::mapped_view_ssh_writer(char * view_base, uint32_t view_size) noexcept
	: _view_base(view_base), _view_size(view_size), _offset(4), _current_object(0)
{
}

void mapped_view_ssh_writer::begin_object()
{
	__try
	{
		if (_view_size - _offset < 4)
			throw std::runtime_error("out of buffer space");

		memcpy(_view_base + _offset, &_current_object, 4);
		_current_object = _offset;
		_offset += 4;
	}
	__except (GetExceptionCode() == STATUS_IN_PAGE_ERROR)
	{
		throw std::runtime_error("in-page error");
	}
}

void mapped_view_ssh_writer::append_data(std::string_view data)
{
	__try
	{
		if (_view_size - _offset < data.size())
			throw std::runtime_error("out of buffer space");
		memcpy(_view_base + _offset, data.data(), data.size());
		_offset += data.size();
	}
	__except (GetExceptionCode() == STATUS_IN_PAGE_ERROR)
	{
		throw std::runtime_error("in-page error");
	}
}

void mapped_view_ssh_writer::end_object()
{
	__try
	{
		uint32_t object_size = _offset - _current_object - 4;
		uint32_t object_size_be = _byteswap_ulong(object_size);

		uint32_t next_object;
		memcpy(&next_object, _view_base + _current_object, 4);
		memcpy(_view_base + _current_object, &object_size_be, sizeof object_size_be);
		_current_object = next_object;
	}
	__except (GetExceptionCode() == STATUS_IN_PAGE_ERROR)
	{
		throw std::runtime_error("in-page error");
	}
}

}
