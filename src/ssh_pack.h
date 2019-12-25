#include <stdint.h>
#include <string_view>
#include "utils.h"

namespace cngeant {

struct ssh_writer
{
	virtual void begin_object() = 0;
	virtual void append_data(std::string_view data) = 0;
	virtual void end_object() = 0;

	virtual void append_object(std::string_view data)
	{
		this->begin_object();
		this->append_data(data);
		this->end_object();
	}

	void push_back(char ch)
	{
		this->append_data({ &ch, 1 });
	}

	void store_u32(uint32_t val)
	{
		uint32_t val_be = to_big_endian(val);
		this->append_data({ (char const *)&val_be, 4 });
	}

	void store_uint(std::string_view data)
	{
		this->begin_object();
		if (data[0] & 0x80)
			this->push_back(0);
		this->append_data(data);
		this->end_object();
	}
};

struct string_ssh_writer final
	: ssh_writer
{
	void begin_object() override;
	void append_data(std::string_view data) override;
	void end_object() override;

	std::string str() &&;

private:
	std::string _str;
	uint32_t _current_object = 0;
};

struct mapped_view_ssh_writer final
	: ssh_writer
{
	mapped_view_ssh_writer(char * view_base, uint32_t view_size) noexcept;

	void begin_object() override;
	void append_data(std::string_view data) override;
	void end_object() override;

private:
	char * _view_base;
	uint32_t _view_size;
	uint32_t _offset;
	uint32_t _current_object;
};

}

#pragma once
