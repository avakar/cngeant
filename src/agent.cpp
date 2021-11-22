#include "agent.h"
#include "pem.h"
#include "utils.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <regex>
#include <system_error>

namespace cngeant {

namespace {

uint32_t _read_u32(std::string_view & in)
{
	if (in.size() < 4)
		throw std::runtime_error("too short");

	uint32_t r;
	memcpy(&r, in.data(), 4);
	r = _byteswap_ulong(r);
	in.remove_prefix(4);
	return r;
}

std::string_view _read_str(std::string_view & in)
{
	uint32_t len = _read_u32(in);
	if (in.size() < len)
		throw std::runtime_error("too short");
	char const * p = in.data();
	in.remove_prefix(len);
	return { p, len };
}

bcrypt_algo_handle _open_bcrypt_algo(LPCWSTR name)
{
	BCRYPT_ALG_HANDLE h;
	auto status = BCryptOpenAlgorithmProvider(&h, name, nullptr, 0);
	if (FAILED(status))
		throw std::system_error(status, std::system_category());
	return bcrypt_algo_handle(h);
}

template <typename T>
static T _ncrypt_get_property(NCRYPT_HANDLE h, LPCWSTR propery_name)
{
	T value;
	DWORD ret_len;
	ncrypt_try NCryptGetProperty(h, propery_name, (PBYTE)&value, sizeof value, &ret_len, NCRYPT_SILENT_FLAG);
	if (ret_len != sizeof value)
		throw std::runtime_error("invalid response size");
	return value;
}

static std::vector<char> _ncrypt_get_property(NCRYPT_HANDLE h, LPCWSTR propery_name)
{
	std::vector<char> value;

	DWORD ret_len;
	ncrypt_try NCryptGetProperty(h, propery_name, nullptr, 0, &ret_len, NCRYPT_SILENT_FLAG);

	value.resize(ret_len);
	ncrypt_try NCryptGetProperty(h, propery_name, (PBYTE)value.data(), value.size(), &ret_len, NCRYPT_SILENT_FLAG);

	value.resize(ret_len);
	return value;
}

struct pubkey_blob_comparator
{
	bool operator()(key_ref const & lhs, key_ref const & rhs) const
	{
		return lhs.public_blob() < rhs.public_blob();
	}

	bool operator()(std::string_view lhs, key_ref const & rhs) const
	{
		return lhs < rhs.public_blob();
	}

	bool operator()(key_ref const & lhs, std::string_view rhs) const
	{
		return lhs.public_blob() < rhs;
	}
};

std::vector<char> _export_key(NCRYPT_KEY_HANDLE key, LPCWSTR blob_type = BCRYPT_PUBLIC_KEY_BLOB)
{
	DWORD export_size;
	ncrypt_try NCryptExportKey(key, 0, blob_type, nullptr, nullptr, 0, &export_size, 0);

	std::vector<char> exported_public_key;
	exported_public_key.resize(export_size);
	ncrypt_try NCryptExportKey(key, 0, blob_type, nullptr,
		(PBYTE)exported_public_key.data(), exported_public_key.size(), &export_size, 0);

	return exported_public_key;
}

void _update_rsa_key_info(key_info & ki)
{
	auto pubkey = _export_key(ki.key.get());
	BCRYPT_RSAKEY_BLOB * blob = (BCRYPT_RSAKEY_BLOB *)pubkey.data();
	if (blob->Magic != BCRYPT_RSAPUBLIC_MAGIC)
		throw std::runtime_error("unknown key blob type");
	char const * key_data = (char const *)(blob + 1);

	ki.algo_id = "ssh-rsa";

	string_ssh_writer wr;
	wr.append_object("ssh-rsa");
	wr.store_uint({ key_data, blob->cbPublicExp });
	wr.store_uint({ key_data + blob->cbPublicExp, blob->cbModulus });
	ki.public_blob = std::move(wr).str();

	ki.sign = [](ssh_writer & wr, bcrypt_algos const & algos, NCRYPT_KEY_HANDLE key, std::string_view tbs, uint32_t flags) {

		wr.begin_object();

		BCRYPT_PKCS1_PADDING_INFO padding_info;

		BYTE digest[64];
		DWORD digest_size;

		NTSTATUS status;
		if (flags == 0)
		{
			wr.append_object("ssh-rsa");
			padding_info.pszAlgId = BCRYPT_SHA1_ALGORITHM;
			digest_size = 20;
			status = BCryptHash(algos.sha1.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, digest_size);
		}
		else if (flags == 2)
		{
			wr.append_object("rsa-sha2-256");
			padding_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
			digest_size = 32;
			status = BCryptHash(algos.sha256.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, digest_size);
		}
		else if (flags == 4)
		{
			wr.append_object("rsa-sha2-512");
			padding_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
			digest_size = 64;
			status = BCryptHash(algos.sha512.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, digest_size);
		}
		else
		{
			throw std::runtime_error("unsupported flags");
		}

		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		std::vector<BYTE> sig;
		DWORD sig_size;
		status = NCryptSignHash(key, &padding_info, digest, digest_size, nullptr, 0, &sig_size, BCRYPT_PAD_PKCS1);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		sig.resize(sig_size);
		status = NCryptSignHash(key, &padding_info, digest, digest_size, sig.data(), sig.size(), &sig_size, BCRYPT_PAD_PKCS1);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		wr.append_object({ (char const *)sig.data(), sig_size });
		wr.end_object();
	};
}

void _update_ecdsa_key_info(key_info & ki, std::string curve)
{
	ki.algo_id = "ecdsa-sha2-" + curve;

	auto pubkey = _export_key(ki.key.get());
	BCRYPT_ECCKEY_BLOB * blob = (BCRYPT_ECCKEY_BLOB *)pubkey.data();

	char const * key_data = (char const *)(blob + 1);

	string_ssh_writer wr;
	wr.append_object(ki.algo_id);
	wr.append_object(curve);

	wr.begin_object();
	wr.push_back(4);
	wr.append_data({ key_data, blob->cbKey });
	wr.append_data({ key_data + blob->cbKey, blob->cbKey });
	wr.end_object();

	ki.public_blob = std::move(wr).str();
}

void _update_ecdsa_p256_key_info(key_info & ki)
{
	_update_ecdsa_key_info(ki, "nistp256");
	ki.sign = [](ssh_writer & wr, bcrypt_algos const & algos, NCRYPT_KEY_HANDLE key, std::string_view tbs, uint32_t flags) {
		if (flags)
			throw std::runtime_error("unsupported flags");

		BYTE digest[32];
		auto status = BCryptHash(algos.sha256.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, sizeof digest);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		BYTE sig[0x40];
		DWORD sig_size;
		status = NCryptSignHash(key, nullptr, digest, sizeof digest, sig, sizeof sig, &sig_size, 0);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		wr.begin_object();

		wr.append_object("ecdsa-sha2-nistp256");

		wr.begin_object();
		wr.store_uint({ (char const *)sig, 0x20 });
		wr.store_uint({ (char const *)sig + 0x20, 0x20 });
		wr.end_object();

		wr.end_object();
	};
}

void _update_ecdsa_p384_key_info(key_info & ki)
{
	_update_ecdsa_key_info(ki, "nistp384");
	ki.sign = [](ssh_writer & wr, bcrypt_algos const & algos, NCRYPT_KEY_HANDLE key, std::string_view tbs, uint32_t flags) {
		if (flags)
			throw std::runtime_error("unsupported flags");

		BYTE digest[48];
		auto status = BCryptHash(algos.sha384.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, sizeof digest);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		BYTE sig[0x60];
		DWORD sig_size;
		status = NCryptSignHash(key, nullptr, digest, sizeof digest, sig, sizeof sig, &sig_size, 0);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		wr.begin_object();

		wr.append_object("ecdsa-sha2-nistp384");

		wr.begin_object();
		wr.store_uint({ (char const *)sig, 0x30 });
		wr.store_uint({ (char const *)sig + 0x30, 0x30 });
		wr.end_object();

		wr.end_object();
	};
}

void _update_ecdsa_p521_key_info(key_info & ki)
{
	_update_ecdsa_key_info(ki, "nistp521");
	ki.sign = [](ssh_writer & wr, bcrypt_algos const & algos, NCRYPT_KEY_HANDLE key, std::string_view tbs, uint32_t flags) {
		if (flags)
			throw std::runtime_error("unsupported flags");

		BYTE digest[64];
		auto status = BCryptHash(algos.sha512.get(), nullptr, 0, (PUCHAR)tbs.data(), tbs.size(), digest, sizeof digest);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		BYTE sig[0x84];
		DWORD sig_size;
		status = NCryptSignHash(key, nullptr, digest, sizeof digest, sig, sizeof sig, &sig_size, 0);
		if (FAILED(status))
			throw std::system_error(status, std::system_category());

		wr.begin_object();

		wr.append_object("ecdsa-sha2-nistp521");

		wr.begin_object();
		wr.store_uint({ (char const *)sig, 0x42 });
		wr.store_uint({ (char const *)sig + 0x42, 0x42 });
		wr.end_object();

		wr.end_object();
	};
}

void _update_ec25519_key_info(key_info & ki)
{
	ki.algo_id = "ssh-ed25519";

	auto pubkey = _export_key(ki.key.get(), BCRYPT_ECCPUBLIC_BLOB);
	BCRYPT_ECCKEY_BLOB * blob = (BCRYPT_ECCKEY_BLOB *)pubkey.data();

	char const * key_data = (char const *)(blob + 1);

	string_ssh_writer wr;
	wr.append_object(ki.algo_id);
	wr.append_object({ key_data, blob->cbKey });
	ki.public_blob = std::move(wr).str();

	ki.sign = [](ssh_writer & wr, bcrypt_algos const & algos, NCRYPT_KEY_HANDLE key, std::string_view tbs, uint32_t flags) {
		if (flags)
			throw std::runtime_error("unsupported flags");

		BYTE sig[64];
		DWORD sig_size;
		ncrypt_try NCryptSignHash(key, nullptr, (PBYTE)tbs.data(), 32, 0, 0, &sig_size, 0);

		wr.begin_object();
		wr.append_object("ssh-ed25519");
		wr.append_object({ (char const *)sig, sig_size });
		wr.end_object();
	};
}

std::wstring _make_key_name(std::string_view comment)
{
	auto r = "ssh-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "-";
	r.append(comment);
	return to_utf16(r);
}

}

bcrypt_algos::bcrypt_algos()
{
	md5 = _open_bcrypt_algo(BCRYPT_MD5_ALGORITHM);
	sha1 = _open_bcrypt_algo(BCRYPT_SHA1_ALGORITHM);
	sha256 = _open_bcrypt_algo(BCRYPT_SHA256_ALGORITHM);
	sha384 = _open_bcrypt_algo(BCRYPT_SHA384_ALGORITHM);
	sha512 = _open_bcrypt_algo(BCRYPT_SHA512_ALGORITHM);
}

std::string key_info::get_public_key() const
{
	std::string r(algo_id);
	r.append(" ");
	r.append(base64(public_blob));
	r.append(" ");
	r.append(comment);
	return r;
}

std::string key_ref::get_public_key() const
{
	return _key->get_public_key();
}

std::string_view key_ref::algo_id() const
{
	return _key->algo_id;
}

std::string_view key_ref::comment() const
{
	return _key->comment;
}

std::string_view key_ref::public_blob() const
{
	return _key->public_blob;
}

bool key_ref::is_hw() const
{
	return _key->is_hw;
}

void key_ref::sign(ssh_writer & wr, bcrypt_algos const & algos, std::string_view tbs, uint32_t flags)
{
	_key->sign(wr, algos, _key->key.get(), tbs, flags);
}

agent::agent()
{
	_sw_provider = std::make_shared<ncrypt_handle>();

	ncrypt_try NCryptOpenStorageProvider(~*_sw_provider, MS_KEY_STORAGE_PROVIDER, 0);
	this->_enum_algos(_sw_provider, false);
	this->_enum_keys(_sw_provider->get(), false);

	_hw_provider = std::make_shared<ncrypt_handle>();
	if (SUCCEEDED(NCryptOpenStorageProvider(~*_hw_provider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)))
	{
		this->_enum_algos(_hw_provider, true);
		this->_enum_keys(_hw_provider->get(), true);
	}
	else
	{
		_hw_provider.reset();
	}

	std::sort(_new_key_types.begin(), _new_key_types.end(), [](new_key_type const & lhs, new_key_type const & rhs) {
		return lhs.score > rhs.score;
		});
	std::sort(_keys.begin(), _keys.end(), pubkey_blob_comparator{});
}

std::vector<std::string> agent::new_key_types()
{
	std::scoped_lock _lock(_mutex);

	std::vector<std::string> r;
	r.reserve(_new_key_types.size());
	for (auto const & nkt: _new_key_types)
		r.push_back(nkt.name);
	return r;
}

void agent::new_key(size_t algo_idx, std::string comment)
{
	auto ki = std::make_shared<key_info>();
	ki->comment = comment;
	_new_key_types.at(algo_idx).create_fn(*ki);

	std::scoped_lock _lock(_mutex);
	_keys.emplace_back(std::move(ki));
}

static std::vector<uint8_t> _read_file(std::filesystem::path const & path)
{
	std::ifstream fin(path, std::ios::binary);
	fin.seekg(0, std::ios::end);
	auto endpos = fin.tellg();
	fin.seekg(0);

	std::vector<uint8_t> r(endpos);
	fin.read((char *)r.data(), r.size());
	return r;
}

void agent::import_key(std::filesystem::path const & path)
{
	auto data = _read_file(path);

	for (auto const & pem: parse_pem(std::string_view{ (char const *)data.data(), data.size() }))
	{
		if (pem.label == "RSA PRIVATE KEY")
		{
			asn1parser p(pem.data);
			p = p.open_structure();

			auto version = p.read_int<int>();
			if (version != 0)
				throw std::runtime_error("unsupported RSA private key version");

			auto modulus = p.read_big_uint();
			auto public_exp = p.read_big_uint();
			auto private_exp = p.read_big_uint();
			auto prime1 = p.read_big_uint();
			auto prime2 = p.read_big_uint();
			auto exp1 = p.read_big_uint();
			auto exp2 = p.read_big_uint();
			auto coeff = p.read_big_uint();
			p.done();

			if (modulus.empty())
				throw std::runtime_error("zero modulus");

			BCRYPT_RSAKEY_BLOB hdr;
			hdr.Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
			hdr.BitLength = modulus.size() * 8;
			hdr.cbModulus = modulus.size();
			hdr.cbPrime1 = prime1.size();
			hdr.cbPrime2 = prime2.size();
			hdr.cbPublicExp = public_exp.size();

			std::vector<std::byte> blob(sizeof hdr + hdr.cbModulus * 2 + hdr.cbPublicExp + hdr.cbPrime1 * 3 + hdr.cbPrime2 * 2);
			memcpy(blob.data(), &hdr, sizeof hdr);
			std::byte * b = blob.data() + sizeof hdr;

			auto store = [&](std::span<std::uint8_t const> chunk, std::size_t req_size) {
				if (chunk.size() > req_size)
					throw std::runtime_error("invalid");
				memset(b, 0, req_size - chunk.size());
				b += req_size - chunk.size();
				memcpy(b, chunk.data(), chunk.size());
				b += chunk.size();
			};

			store(public_exp, hdr.cbPublicExp);
			store(modulus, hdr.cbModulus);
			store(prime1, hdr.cbPrime1);
			store(prime2, hdr.cbPrime2);
			store(exp1, hdr.cbPrime1);
			store(exp2, hdr.cbPrime2);
			store(coeff, hdr.cbPrime1);
			store(private_exp, hdr.cbModulus);

			auto ki = std::make_shared<key_info>();
			ki->comment = path.stem().string();

			auto try_prov = [&](auto const & provider, bool is_hw) {
				try
				{
					ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki->key, BCRYPT_RSA_ALGORITHM, _make_key_name(ki->comment).c_str(), 0, 0);
					ncrypt_try NCryptSetProperty(ki->key.get(), BCRYPT_RSAFULLPRIVATE_BLOB, (PBYTE)blob.data(), blob.size(), NCRYPT_SILENT_FLAG);
					ncrypt_try NCryptFinalizeKey(ki->key.get(), NCRYPT_SILENT_FLAG);
					ki->is_hw = is_hw;
					return true;
				}
				catch (...)
				{
					return false;
				}
			};

			if (!_hw_provider || !try_prov(_hw_provider, true))
				try_prov(_sw_provider, false);

			_update_rsa_key_info(*ki);

			std::scoped_lock _lock(_mutex);
			_keys.emplace_back(std::move(ki));
		}
	}
}

bool agent::process_message(ssh_writer & wr, std::string_view msg)
{
	if (msg.empty())
		return false;

	uint8_t type = msg[0];
	msg.remove_prefix(1);

	switch (type)
	{
	case 11:
	{
		std::scoped_lock _lock(_mutex);

		wr.push_back(12);
		wr.store_u32(_keys.size());
		for (key_ref const & key: _keys)
		{
			wr.append_object(key.public_blob());
			wr.append_object(key.comment());
		}
		return true;
	}
	case 13: // SSH2_AGENTC_SIGN_REQUEST
	{
		auto key = _read_str(msg);
		auto tbs = _read_str(msg);

		uint32_t flags = 0;
		if (!msg.empty())
			flags = _read_u32(msg);

		std::scoped_lock _lock(_mutex);
		auto [it, last] = std::equal_range(_keys.begin(), _keys.end(), key, pubkey_blob_comparator{});
		if (it == last)
			return false;

		wr.push_back(14);
		it->sign(wr, _algos, tbs, flags);
		return true;
	}
	default:
		return false;
	}
}

void agent::delete_key(key_ref key)
{
	ncrypt_try NCryptDeleteKey(key._key->key.get(), 0);
	key._key->key.release();

	std::scoped_lock _lock(_mutex);
	_keys.erase(
		std::remove(_keys.begin(), _keys.end(), key),
		_keys.end());
}

std::vector<key_ref> agent::keys() const
{
	std::scoped_lock _lock(_mutex);
	return _keys;
}

void agent::_enum_algos(std::shared_ptr<ncrypt_handle> provider, bool is_hw)
{
	DWORD alg_count;
	NCryptAlgorithmName * algos = nullptr;
	ncrypt_try NCryptEnumAlgorithms(provider->get(), NCRYPT_SIGNATURE_OPERATION, &alg_count, &algos, NCRYPT_SILENT_FLAG);
	defer{ NCryptFreeBuffer(algos); };

	auto add_algo = [&](std::string name, double bits_of_security, int pubkey_len, auto const & factory) {
		double score = bits_of_security - pubkey_len / 3.0;
		if (is_hw)
		{
			score += 20.0;
			name.append("-tpm");
		}

		_new_key_types.push_back({ name, score, [factory, is_hw](key_info & ki) {
			ki.is_hw = is_hw;
			factory(ki);
			} });
	};

	for (DWORD i = 0; i != alg_count; ++i)
	{
		std::wstring_view algo_name = algos[i].pszName;
		if (algo_name == BCRYPT_RSA_ALGORITHM)
		{
			ncrypt_handle key;
			ncrypt_try NCryptCreatePersistedKey(provider->get(), ~key, BCRYPT_RSA_ALGORITHM, nullptr, 0, 0);

			auto lengths = _ncrypt_get_property<NCRYPT_SUPPORTED_LENGTHS>(key.get(), NCRYPT_LENGTHS_PROPERTY);

			auto add_rsa = [&](DWORD len) {
				if (len < lengths.dwMinLength
					|| len > lengths.dwMaxLength
					|| (lengths.dwMinLength - len) % lengths.dwIncrement != 0)
				{
					return;
				}

				add_algo("rsa-" + std::to_string(len), len * (80.0 / 1024), len / 8, [this, len, provider](key_info & ki) {
					ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki.key, BCRYPT_RSA_ALGORITHM, _make_key_name(ki.comment).c_str(), 0, 0);
					ncrypt_try NCryptSetProperty(ki.key.get(), NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof len, NCRYPT_SILENT_FLAG);
					ncrypt_try NCryptFinalizeKey(ki.key.get(), NCRYPT_SILENT_FLAG);
					_update_rsa_key_info(ki);
					});
			};

			add_rsa(1024);
			add_rsa(2048);
			add_rsa(3072);
			add_rsa(4096);
		}
		else if (algo_name == BCRYPT_ECDSA_P256_ALGORITHM)
		{
			add_algo("ecdsa-sha2-nistp256", 128, 64, [this, provider](key_info & ki) {
				ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki.key, BCRYPT_ECDSA_P256_ALGORITHM, _make_key_name(ki.comment).c_str(), 0, 0);
				ncrypt_try NCryptFinalizeKey(ki.key.get(), NCRYPT_SILENT_FLAG);
				_update_ecdsa_p256_key_info(ki);
				});
		}
		else if (algo_name == BCRYPT_ECDSA_P384_ALGORITHM)
		{
			add_algo("ecdsa-sha2-nistp384", 192, 96, [this, provider](key_info & ki) {
				ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki.key, BCRYPT_ECDSA_P384_ALGORITHM, _make_key_name(ki.comment).c_str(), 0, 0);
				ncrypt_try NCryptFinalizeKey(ki.key.get(), NCRYPT_SILENT_FLAG);
				_update_ecdsa_p384_key_info(ki);
				});
		}
		else if (algo_name == BCRYPT_ECDSA_P521_ALGORITHM)
		{
			add_algo("ecdsa-sha2-nistp521", 256, 128, [this, provider](key_info & ki) {
				ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki.key, BCRYPT_ECDSA_P521_ALGORITHM, _make_key_name(ki.comment).c_str(), 0, 0);
				ncrypt_try NCryptFinalizeKey(ki.key.get(), NCRYPT_SILENT_FLAG);
				_update_ecdsa_p521_key_info(ki);
				});
		}
		else if (algo_name == BCRYPT_ECDSA_ALGORITHM)
		{
			ncrypt_handle key;
			ncrypt_try NCryptCreatePersistedKey(provider->get(), ~key, BCRYPT_ECDSA_ALGORITHM, nullptr, 0, 0);

			std::vector<char> buf;
			try
			{
				buf = _ncrypt_get_property(key.get(), NCRYPT_ECC_CURVE_NAME_LIST_PROPERTY);
			}
			catch (std::exception const &)
			{
			}

			key.reset();

			if (buf.size() >= sizeof(BCRYPT_ECC_CURVE_NAMES))
			{
				BCRYPT_ECC_CURVE_NAMES * curve_list = (BCRYPT_ECC_CURVE_NAMES *)buf.data();
				for (ULONG i = 0; i != curve_list->dwEccCurveNames; ++i)
				{
					std::wstring_view curve_name = curve_list->pEccCurveNames[i];
					if (curve_name == BCRYPT_ECC_CURVE_25519)
					{
						add_algo("ssh-ed25519", 125, 64, [this, provider](key_info & ki) {
							ncrypt_try NCryptCreatePersistedKey(provider->get(), ~ki.key, BCRYPT_ECDSA_ALGORITHM, _make_key_name(ki.comment).c_str(), 0, 0);
							ncrypt_try NCryptSetProperty(ki.key.get(), NCRYPT_ECC_CURVE_NAME_PROPERTY, (PBYTE)BCRYPT_ECC_CURVE_25519, sizeof BCRYPT_ECC_CURVE_25519, 0);
							ncrypt_try NCryptFinalizeKey(ki.key.get(), NCRYPT_SILENT_FLAG);
							_update_ec25519_key_info(ki);
							});
					}
				}
			}
		}
	}
}

static std::wregex _key_name_re(L"ssh-\\d+-(.*)");

void agent::_enum_keys(NCRYPT_PROV_HANDLE provider, bool is_hw)
{
	PVOID enum_state = nullptr;
	defer{ if (enum_state) NCryptFreeBuffer(enum_state); };
	for (;;)
	{
		NCryptKeyName * key_name;
		auto status = NCryptEnumKeys(provider, nullptr, &key_name, &enum_state, NCRYPT_SILENT_FLAG);
		if (FAILED(status))
			break;
		defer{ NCryptFreeBuffer(key_name); };

		std::wstring name(key_name->pszName);
		std::wsmatch m;
		if (!std::regex_match(name, m, _key_name_re))
			continue;

		std::wstring_view algo_id = key_name->pszAlgid;

		auto ki = std::make_shared<key_info>();
		ki->comment = to_utf8(m[1].str());
		ki->is_hw = is_hw;
		ncrypt_try NCryptOpenKey(provider, ~ki->key, key_name->pszName, 0, NCRYPT_SILENT_FLAG);

		if (algo_id == BCRYPT_RSA_ALGORITHM)
		{
			_update_rsa_key_info(*ki);
		}
		else if (algo_id == BCRYPT_ECDSA_P256_ALGORITHM)
		{
			_update_ecdsa_p256_key_info(*ki);
		}
		else if (algo_id == BCRYPT_ECDSA_P384_ALGORITHM)
		{
			_update_ecdsa_p384_key_info(*ki);
		}
		else if (algo_id == BCRYPT_ECDSA_P521_ALGORITHM)
		{
			_update_ecdsa_p521_key_info(*ki);
		}
		else if (algo_id == BCRYPT_ECDSA_ALGORITHM || algo_id == BCRYPT_ECDH_ALGORITHM)
		{
			auto buf = _ncrypt_get_property(ki->key.get(), NCRYPT_ECC_CURVE_NAME_PROPERTY);
			std::wstring_view curve_name = (wchar_t const *)buf.data();

			if (curve_name == BCRYPT_ECC_CURVE_NISTP256)
			{
				_update_ecdsa_p256_key_info(*ki);
			}
			else if (curve_name == BCRYPT_ECC_CURVE_NISTP384)
			{
				_update_ecdsa_p384_key_info(*ki);
			}
			else if (curve_name == BCRYPT_ECC_CURVE_NISTP521)
			{
				_update_ecdsa_p521_key_info(*ki);
			}
			else if (curve_name == BCRYPT_ECC_CURVE_25519)
			{
				_update_ec25519_key_info(*ki);
			}
		}

		_keys.emplace_back(std::move(ki));
	}
}

}
