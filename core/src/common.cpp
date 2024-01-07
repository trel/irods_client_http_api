#include "irods/private/http_api/common.hpp"

#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/process_stash.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h> // For addKeyVal().
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h> // For KW_CLOSE_OPEN_REPLICAS.
#include <irods/switch_user.h>
#include <irods/ticketAdmin.h>

#include <boost/any.hpp>
#include <boost/algorithm/string.hpp>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <string>

namespace irods::http
{
	auto fail(response_type& _response, status_type _status, const std::string_view _error_msg) -> response_type
	{
		_response.result(_status);
		_response.set(field_type::server, version::server_name);
		_response.set(field_type::content_type, "application/json");
		_response.body() = _error_msg;
		_response.prepare_payload();
		return _response;
	} // fail

	auto fail(response_type& _response, status_type _status) -> response_type
	{
		return fail(_response, _status, "");
	} // fail

	auto fail(status_type _status, const std::string_view _error_msg) -> response_type
	{
		response_type r{_status, 11};
		return fail(r, _status, _error_msg);
	} // fail

	auto fail(status_type _status) -> response_type
	{
		response_type r{_status, 11};
		return fail(r, _status, "");
	} // fail

	auto decode(const std::string_view _v) -> std::string
	{
		std::string result;
		int decoded_length = -1;

		if (auto* decoded = curl_easy_unescape(nullptr, _v.data(), static_cast<int>(_v.size()), &decoded_length);
		    decoded) {
			std::unique_ptr<char, void (*)(void*)> s{decoded, curl_free};
			result.assign(decoded, decoded_length);
		}
		else {
			result.assign(_v);
		}

		return result;
	} // decode

	auto encode(std::string_view _to_encode) -> std::string
	{
		char* tmp_encoded_data{curl_easy_escape(nullptr, _to_encode.data(), _to_encode.size())};
		if (tmp_encoded_data == nullptr) {
			return {std::cbegin(_to_encode), std::cend(_to_encode)};
		}

		std::string encoded_data{tmp_encoded_data};

		curl_free(tmp_encoded_data);
		return encoded_data;
	} // encode

	// TODO Create a better name.
	auto to_argument_list(const std::string_view _urlencoded_string) -> std::unordered_map<std::string, std::string>
	{
		if (_urlencoded_string.empty()) {
			return {};
		}

		std::unordered_map<std::string, std::string> kvps;

		std::vector<std::string> tokens;
		boost::split(tokens, _urlencoded_string, boost::is_any_of("&"));

		std::vector<std::string> kvp;

		for (auto&& t : tokens) {
			boost::split(kvp, t, boost::is_any_of("="));

			if (kvp.size() == 2) {
				auto value = decode(kvp[1]);
				boost::replace_all(value, "+", " ");
				kvps.insert_or_assign(std::move(kvp[0]), value);
			}
			else if (kvp.size() == 1) {
				kvps.insert_or_assign(std::move(kvp[0]), "");
			}

			kvp.clear();
		}

		return kvps;
	} // to_argument_list

	auto get_url_path(const std::string& _url) -> std::optional<std::string>
	{
		namespace log = irods::http::log;

		std::unique_ptr<CURLU, void (*)(CURLU*)> curl{curl_url(), curl_url_cleanup};

		if (!curl) {
			log::error("{}: Could not initialize libcurl.", __func__);
			return std::nullopt;
		}

		if (const auto ec = curl_url_set(curl.get(), CURLUPART_URL, _url.c_str(), 0); ec) {
			log::error("{}: curl_url_set error: {}", __func__, ec);
			return std::nullopt;
		}

		using curl_string = std::unique_ptr<char, void (*)(void*)>;

		// Extract the path.
		// This is what we use to route requests to the various endpoints.
		char* path{};
		const auto ec = curl_url_get(curl.get(), CURLUPART_PATH, &path, 0);

		if (ec == 0) {
			curl_string cpath{path, curl_free};
			return path;
		}

		log::error("{}: curl_url_get(CURLUPART_PATH) error: {}", __func__, ec);
		return std::nullopt;
	} // get_url_path

	auto parse_url(const std::string& _url) -> url
	{
		namespace log = irods::http::log;

		std::unique_ptr<CURLU, void (*)(CURLU*)> curl{curl_url(), curl_url_cleanup};

		if (!curl) {
			log::error("{}: Could not initialize CURLU handle.", __func__);
			THROW(SYS_LIBRARY_ERROR, "curl_url error.");
		}

		// Include a bogus prefix. We only care about the path and query parts of the URL.
		if (const auto ec = curl_url_set(curl.get(), CURLUPART_URL, _url.c_str(), 0); ec) {
			log::error("{}: curl_url_set error: {}", __func__, ec);
			THROW(SYS_LIBRARY_ERROR, "curl_url_set(CURLUPART_URL) error.");
		}

		url url;

		using curl_string = std::unique_ptr<char, void (*)(void*)>;

		// Extract the path.
		// This is what we use to route requests to the various endpoints.
		char* path{};
		if (const auto ec = curl_url_get(curl.get(), CURLUPART_PATH, &path, 0); ec == 0) {
			curl_string cpath{path, curl_free};
			if (path) {
				url.path = path;
			}
		}
		else {
			log::error("{}: curl_url_get(CURLUPART_PATH) error: {}", __func__, ec);
			THROW(SYS_LIBRARY_ERROR, "curl_url_get(CURLUPART_PATH) error.");
		}

		// Extract the query.
		// ChatGPT states that the values in the key value pairs must escape embedded equal signs.
		// This allows the HTTP server to parse the query string correctly. Therefore, we don't have
		// to protect against that case. The client must send the correct URL escaped input.
		char* query{};
		if (const auto ec = curl_url_get(curl.get(), CURLUPART_QUERY, &query, 0); ec == 0) {
			curl_string cs{query, curl_free};
			if (query) {
				url.query = to_argument_list(query);
			}
		}
		else {
			log::error("{}: curl_url_get(CURLUPART_QUERY) error: {}", __func__, ec);
			THROW(SYS_LIBRARY_ERROR, "curl_url_get(CURLUPART_QUERY) error.");
		}

		return url;
	} // parse_url

	auto parse_url(const request_type& _req) -> url
	{
		return parse_url(fmt::format("http://ignored{}", _req.target()));
	} // parse_url

	auto resolve_client_identity(const request_type& _req) -> client_identity_resolution_result
	{
		namespace log = irods::http::log;

		//
		// Extract the Bearer token from the Authorization header.
		//

		const auto& hdrs = _req.base();
		const auto iter = hdrs.find("Authorization");
		if (iter == std::end(hdrs)) {
			log::error("{}: Missing [Authorization] header.", __func__);
			return {.response = fail(status_type::bad_request)};
		}

		log::debug("{}: Authorization value: [{}]", __func__, iter->value());

		auto pos = iter->value().find("Bearer ");
		if (std::string_view::npos == pos) {
			log::debug("{}: Malformed authorization header.", __func__);
			return {.response = fail(status_type::bad_request)};
		}

		std::string bearer_token{iter->value().substr(pos + 7)};
		boost::trim(bearer_token);
		log::debug("{}: Bearer token: [{}]", __func__, bearer_token);

		// Verify the bearer token is known to the server. If not, return an error.
		auto mapped_value{irods::http::process_stash::find(bearer_token)};
		if (!mapped_value.has_value()) {
			log::error("{}: Could not find bearer token matching [{}].", __func__, bearer_token);
			return {.response = fail(status_type::unauthorized)};
		}

		auto* client_info{boost::any_cast<authenticated_client_info>(&*mapped_value)};
		if (client_info == nullptr) {
			log::error("{}: Could not find bearer token matching [{}].", __func__, bearer_token);
			return {.response = fail(status_type::unauthorized)};
		}

		if (std::chrono::steady_clock::now() >= client_info->expires_at) {
			log::error("{}: Session for bearer token [{}] has expired.", __func__, bearer_token);
			return {.response = fail(status_type::unauthorized)};
		}

		log::trace("{}: Client is authenticated.", __func__);
		return {.client_info = std::move(*client_info)};
	} // resolve_client_identity
} // namespace irods::http

namespace irods
{
	auto to_permission_string(const irods::experimental::filesystem::perms _p) -> const char*
	{
		using irods::experimental::filesystem::perms;

		// clang-format off
		switch (_p) {
			case perms::null:            return "null";
			case perms::read_metadata:   return "read_metadata";
			case perms::read_object:
			case perms::read:            return "read_object";
			case perms::create_metadata: return "create_metadata";
			case perms::modify_metadata: return "modify_metadata";
			case perms::delete_metadata: return "delete_metadata";
			case perms::create_object:   return "create_object";
			case perms::modify_object:
			case perms::write:           return "modify_object";
			case perms::delete_object:   return "delete_object";
			case perms::own:             return "own";
		}
		// clang-format on

		THROW(SYS_INVALID_INPUT_PARAM, fmt::format("Cannot convert permission enumeration to string."));
	} // to_permission_string

	auto to_permission_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::perms>
	{
		using irods::experimental::filesystem::perms;

		// clang-format off
		if (_s == "null")            { return perms::null; }
		if (_s == "read_metadata")   { return perms::read_metadata; }
		if (_s == "read_object")     { return perms::read; }
		if (_s == "read")            { return perms::read; }
		if (_s == "create_metadata") { return perms::create_metadata; }
		if (_s == "modify_metadata") { return perms::modify_metadata; }
		if (_s == "delete_metadata") { return perms::delete_metadata; }
		if (_s == "create_object")   { return perms::create_object; }
		if (_s == "modify_object")   { return perms::write; }
		if (_s == "write")           { return perms::write; }
		if (_s == "delete_object")   { return perms::delete_object; }
		if (_s == "own")             { return perms::own; }
		// clang-format on

		return std::nullopt;
	} // to_permission_enum

	auto to_object_type_string(const irods::experimental::filesystem::object_type _t) -> const char*
	{
		using irods::experimental::filesystem::object_type;

		// clang-format off
		switch (_t) {
			case object_type::collection:         return "collection";
			case object_type::data_object:        return "data_object";
			case object_type::none:               return "none";
			case object_type::not_found:          return "not_found";
			case object_type::special_collection: return "special_collection";
			case object_type::unknown:            return "unknown";
			default:                              return "?";
		}
		// clang-format on
	} // to_object_type_string

	auto to_object_type_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::object_type>
	{
		using irods::experimental::filesystem::object_type;

		// clang-format off
		if (_s == "collection")         { return object_type::collection; }
		if (_s == "data_object")        { return object_type::data_object; }
		if (_s == "none")               { return object_type::none; }
		if (_s == "not_found")          { return object_type::not_found; }
		if (_s == "special_collection") { return object_type::special_collection; }
		if (_s == "unknown")            { return object_type::unknown; }
		// clang-format on

		return std::nullopt;
	} // to_object_type_enum

	auto get_connection(const std::string& _username) -> irods::http::connection_facade
	{
		namespace log = irods::http::log;
		using json_pointer = nlohmann::json::json_pointer;

		static const auto& config = irods::http::globals::configuration();
		static const auto& irods_client_config = config.at("irods_client");
		static const auto& zone = irods_client_config.at("zone").get_ref<const std::string&>();

		if (config.at(json_pointer{"/irods_client/enable_4_2_compatibility"}).get<bool>()) {
			static const auto& rodsadmin_username =
				irods_client_config.at(json_pointer{"/proxy_admin_account/username"}).get_ref<const std::string&>();
			static auto rodsadmin_password =
				irods_client_config.at(json_pointer{"/proxy_admin_account/password"}).get_ref<const std::string&>();

			irods::experimental::client_connection conn{
				irods::experimental::defer_authentication,
				irods_client_config.at("host").get_ref<const std::string&>(),
				irods_client_config.at("port").get<int>(),
				{rodsadmin_username, zone},
				{_username, zone}};

			auto* conn_ptr = static_cast<RcComm*>(conn);

			if (const auto ec = clientLoginWithPassword(conn_ptr, rodsadmin_password.data()); ec < 0) {
				log::error("{}: clientLoginWithPassword error: {}", __func__, ec);
				THROW(SYS_INTERNAL_ERR, "clientLoginWithPassword error.");
			}

			return irods::http::connection_facade{std::move(conn)};
		}

		auto conn = irods::http::globals::connection_pool().get_connection();

		log::trace("{}: Changing identity associated with connection to [{}].", __func__, _username);

		SwitchUserInput input{};

		irods::at_scope_exit clear_options{[&input] { clearKeyVal(&input.options); }};

		std::strncpy(input.username, _username.c_str(), sizeof(SwitchUserInput::username) - 1);
		std::strncpy(input.zone, zone.c_str(), sizeof(SwitchUserInput::zone) - 1);
		addKeyVal(&input.options, KW_CLOSE_OPEN_REPLICAS, "");

		if (const auto ec = rc_switch_user(static_cast<RcComm*>(conn), &input); ec < 0) {
			log::error("{}: rc_switch_user error: {}", __func__, ec);
			THROW(ec, "rc_switch_user error.");
		}

		log::trace("{}: Successfully changed identity associated with connection to [{}].", __func__, _username);

		return irods::http::connection_facade{std::move(conn)};
	} // get_connection

	auto fail(boost::beast::error_code ec, char const* what) -> void
	{
		irods::http::log::error("{}: {}: {}", __func__, what, ec.message());
	} // fail

	auto enable_ticket(RcComm& _comm, const std::string& _ticket) -> int
	{
		TicketAdminInput input{};
		input.arg1 = const_cast<char*>("session"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
		input.arg2 = const_cast<char*>(_ticket.c_str()); // NOLINT(cppcoreguidelines-pro-type-const-cast)
		input.arg3 = const_cast<char*>(""); // NOLINT(cppcoreguidelines-pro-type-const-cast)

		return rcTicketAdmin(&_comm, &input);
	} // enable_ticket
} // namespace irods
