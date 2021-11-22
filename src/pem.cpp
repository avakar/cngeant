#include "pem.h"
#include <array>
#include <regex>

static constexpr std::array<int8_t, 256> _transpose(char const * p)
{
	std::array<int8_t, 256> r = {};
	for (auto & x : r)
		x = -1;

	std::int8_t i = 0;
	while (*p)
	{
		auto v = (std::uint8_t)*p++;
		r[v] = i++;
	}

	return r;
}

static constexpr char _base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static constexpr std::array<int8_t, 256> _base64_inv = _transpose(_base64_chars);

static std::vector<uint8_t> unbase64(std::string_view data)
{
	char const * p = data.data();
	char const * last = p + data.size();

	auto getch = [&]() -> char {
		while (p != last)
		{
			char c = *p++;
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
				continue;

			return c;
		}

		return 0;
	};

	std::vector<uint8_t> r;

	std::uint32_t w = 0;
	int wl = 0;

	while (char c = getch())
	{
		if (c == '=')
		{
			switch (wl)
			{
			case 2:
				if (getch() == '=' && getch() == 0 && (w & 0xf) == 0)
				{
					r.push_back(w >> 4);
					return r;
				}

				break;
			case 3:
				if (getch() == 0 && (w & 3) == 0)
				{
					r.push_back(w >> 10);
					r.push_back(w >> 2);
					return r;
				}

				break;
			}

			throw std::runtime_error("unexpected padding");
		}

		std::int8_t v = _base64_inv[c];
		if (v == -1)
			throw std::runtime_error("invalid base64");
		__assume(v >= 0);

		w = (w << 6) | v;
		if (++wl == 4)
		{
			r.push_back(w >> 16);
			r.push_back(w >> 8);
			r.push_back(w & 0xff);
			wl = 0;
		}
	}

	if (wl != 0)
		throw std::runtime_error("truncated base64");

	return r;
}

static std::regex const _preenc_re("-----BEGIN ((?:[!-,.-~]+(?:[- ][!-,.-~]+)*)?)-----");

std::vector<pem_object> parse_pem(std::string_view data)
{
	char const * p = data.data();
	char const * last = p + data.size();

	std::vector<pem_object> r;
	
	std::cmatch m;
	for (;;)
	{
		if (!std::regex_search(p, last, m, _preenc_re))
			return r;

		std::string label = m[1].str();
		char const * cur = m[0].second;

		auto postenc = "-----END " + std::string(label) + "-----";

		auto postenc_pos = data.find(postenc, cur - p);
		if (postenc_pos == std::string_view::npos)
			throw std::runtime_error("missing post-encoding boundary");

		char const * e = p + postenc_pos;
		p = e + postenc.size();

		r.push_back({ std::move(label), unbase64(std::string_view{cur, std::size_t(e - cur)}) });
	}
}
