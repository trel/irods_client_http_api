#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/handlers.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/process_stash.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/connection_pool.hpp>
#include <irods/fully_qualified_username.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/rodsClient.h>

#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// __has_feature is a Clang specific feature.
// The preprocessor code below exists so that other compilers can be used (e.g. GCC).
#ifndef __has_feature
#  define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
// Defines default options for running the HTTP API with Address Sanitizer enabled.
// This is a convenience function which allows the HTTP API to start without needing the
// administrator to specify options via environment variables.
extern "C" const char* __asan_default_options()
{
	// See root CMakeLists.txt file for definition.
	return IRODS_ADDRESS_SANITIZER_DEFAULT_OPTIONS;
} // __asan_default_options
#endif

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
namespace po    = boost::program_options;
namespace log   = irods::http::log;

using json = nlohmann::json;
using tcp  = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// IRODS_HTTP_API_BASE_URL is a macro defined by the CMakeLists.txt.
const irods::http::request_handler_map_type req_handlers{
	{IRODS_HTTP_API_BASE_URL "/authenticate", irods::http::handler::authentication},
	{IRODS_HTTP_API_BASE_URL "/collections",  irods::http::handler::collections},
	//{IRODS_HTTP_API_BASE_URL "/config",       irods::http::handler::configuration},
	{IRODS_HTTP_API_BASE_URL "/data-objects", irods::http::handler::data_objects},
	{IRODS_HTTP_API_BASE_URL "/info",         irods::http::handler::information},
	{IRODS_HTTP_API_BASE_URL "/query",        irods::http::handler::query},
	{IRODS_HTTP_API_BASE_URL "/resources",    irods::http::handler::resources},
	{IRODS_HTTP_API_BASE_URL "/rules",        irods::http::handler::rules},
	{IRODS_HTTP_API_BASE_URL "/tickets",      irods::http::handler::tickets},
	{IRODS_HTTP_API_BASE_URL "/users-groups", irods::http::handler::users_groups},
	{IRODS_HTTP_API_BASE_URL "/zones",        irods::http::handler::zones}
};
// clang-format on

// Accepts incoming connections and launches the sessions.
class listener : public std::enable_shared_from_this<listener>
{
  public:
	listener(net::io_context& ioc, const tcp::endpoint& endpoint, const json& _config)
		: ioc_{ioc}
		, acceptor_{net::make_strand(ioc)}
		, max_rbuffer_size_{_config.at(json::json_pointer{"/http_server/requests/max_rbuffer_size_in_bytes"})
	                            .get<int>()}
		, timeout_in_secs_{_config.at(json::json_pointer{"/http_server/requests/timeout_in_seconds"}).get<int>()}
	{
		beast::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec) {
			irods::fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
		if (ec) {
			irods::fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec) {
			irods::fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(net::socket_base::max_listen_connections, ec);
		if (ec) {
			irods::fail(ec, "listen");
			return;
		}
	} // listener (constructor)

	// Start accepting incoming connections.
	auto run() -> void
	{
		do_accept();
	} // run

  private:
	auto do_accept() -> void
	{
		// The new connection gets its own strand
		acceptor_.async_accept(
			net::make_strand(ioc_), beast::bind_front_handler(&listener::on_accept, shared_from_this()));
	} // do_accept

	auto on_accept(beast::error_code ec, tcp::socket socket) -> void
	{
		if (ec) {
			irods::fail(ec, "accept");
			//return; // To avoid infinite loop
		}
		else {
			// Create the session and run it
			std::make_shared<irods::http::session>(std::move(socket), req_handlers, max_rbuffer_size_, timeout_in_secs_)
				->run();
		}

		// Accept another connection
		do_accept();
	} // on_accept

	net::io_context& ioc_;
	tcp::acceptor acceptor_;
	const int max_rbuffer_size_;
	const int timeout_in_secs_;
}; // class listener

auto print_version_info() -> void
{
	namespace version = irods::http::version;
	const std::string_view sha = version::sha;
	constexpr auto sha_size = 7;
	fmt::print("{} v{}-{}\n", version::binary_name, version::api_version, sha.substr(0, sha_size));
} // print_version_info

auto print_configuration_template() -> void
{
	fmt::print(R"({{
    "http_server": {{
        "host": "0.0.0.0",
        "port": 9000,

        "log_level": "info",

        "authentication": {{
            "eviction_check_interval_in_seconds": 60,

            "basic": {{
                "timeout_in_seconds": 3600
            }},

            "oidc": {{
                "config_host": "<string>",
                "port": 8080,
                "well_known_uri": "<string>",
                "client_id": "<string>",
                "redirect_uri": "<string>"
            }}
        }},

        "requests": {{
            "threads": 3,
            "max_rbuffer_size_in_bytes": 8388608,
            "timeout_in_seconds": 30
        }},

        "background_io": {{
            "threads": 6
        }}
    }},

    "irods_client": {{
        "host": "<string>",
        "port": 1247,
        "zone": "<string>",

        "tls": {{
            "client_server_policy": "<string>",
            "ca_certificate_file": "<string>",
            "certificate_chain_file": "<string>",
            "dh_params_file": "<string>",
            "verify_server": "<string>"
        }},

        "enable_4_2_compatibility": false,

        "proxy_admin_account": {{
            "username": "<string>",
            "password": "<string>"
        }},

        "connection_pool": {{
            "size": 6,
            "refresh_timeout_in_seconds": 600,
            "max_retrievals_before_refresh": 16,
            "refresh_when_resource_changes_detected": true
        }},

        "max_number_of_parallel_write_streams": 3,

        "max_number_of_bytes_per_read_operation": 8192,
        "buffer_size_in_bytes_for_write_operations": 8192,

        "max_number_of_rows_per_catalog_query": 15
    }}
}}
)");
} // print_configuration_template

auto print_usage() -> void
{
	fmt::print(R"_(irods_http_api - Exposes the iRODS API over HTTP

Usage: irods_http_api [OPTION]... CONFIG_FILE_PATH

CONFIG_FILE_PATH must point to a file containing a JSON structure containing
configuration options.

--dump-config-template can be used to generate a default configuration file.
See this option's description for more information.

Options:
      --dump-config-template
                     Print configuration template to stdout and exit. Some
                     options have values which act as placeholders. If used
                     to generate a configuration file, those options will
                     need to be updated.
  -h, --help         Display this help message and exit.
  -v, --version      Display version information and exit.

)_");

	print_version_info();
} // print_usage

auto set_log_level(const json& _config) -> void
{
	const auto iter = _config.find("log_level");

	if (iter == std::end(_config)) {
		spdlog::set_level(spdlog::level::info);
	}

	const auto& lvl_string = iter->get_ref<const std::string&>();
	auto lvl_enum = spdlog::level::info;

	// clang-format off
	if      (lvl_string == "trace")    { lvl_enum = spdlog::level::trace; }
	else if (lvl_string == "info")     { lvl_enum = spdlog::level::info; }
	else if (lvl_string == "debug")    { lvl_enum = spdlog::level::debug; }
	else if (lvl_string == "warn")     { lvl_enum = spdlog::level::warn; }
	else if (lvl_string == "error")    { lvl_enum = spdlog::level::err; }
	else if (lvl_string == "critical") { lvl_enum = spdlog::level::critical; }
	else                               { log::warn("Invalid log_level. Setting to [info]."); }
	// clang-format on

	spdlog::set_level(lvl_enum);
} // set_log_level

auto init_tls(const json& _config) -> void
{
	const auto set_env_var = [&](const auto& _json_ptr_path, const char* _env_var, const char* _default_value = "") {
		using json_ptr = json::json_pointer;

		if (const auto v = _config.value(json_ptr{_json_ptr_path}, _default_value); !v.empty()) {
			const auto env_var_upper = boost::to_upper_copy<std::string>(_env_var);
			log::trace("Setting environment variable [{}] to [{}].", env_var_upper, v);
			setenv(env_var_upper.c_str(), v.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
		}
	};

	set_env_var("/irods_client/tls/client_server_policy", irods::KW_CFG_IRODS_CLIENT_SERVER_POLICY, "CS_NEG_REFUSE");
	set_env_var("/irods_client/tls/ca_certificate_file", irods::KW_CFG_IRODS_SSL_CA_CERTIFICATE_FILE);
	set_env_var("/irods_client/tls/certificate_chain_file", irods::KW_CFG_IRODS_SSL_CERTIFICATE_CHAIN_FILE);
	set_env_var("/irods_client/tls/dh_params_file", irods::KW_CFG_IRODS_SSL_DH_PARAMS_FILE);
	set_env_var("/irods_client/tls/verify_server", irods::KW_CFG_IRODS_SSL_VERIFY_SERVER, "cert");
} // init_tls

auto init_irods_connection_pool(const json& _config) -> std::unique_ptr<irods::connection_pool>
{
	const auto& client = _config.at("irods_client");
	const auto& zone = client.at("zone").get_ref<const std::string&>();
	const auto& conn_pool = client.at("connection_pool");
	const auto& rodsadmin = client.at("proxy_admin_account");
	const auto& username = rodsadmin.at("username").get_ref<const std::string&>();

	irods::connection_pool_options opts;

	if (const auto iter = conn_pool.find("refresh_time_in_seconds"); iter != std::end(conn_pool)) {
		opts.number_of_seconds_before_connection_refresh = std::chrono::seconds{iter->get<int>()};
	}

	if (const auto iter = conn_pool.find("max_retrievals_before_refresh"); iter != std::end(conn_pool)) {
		opts.number_of_retrievals_before_connection_refresh = iter->get<std::int16_t>();
	}

	if (const auto iter = conn_pool.find("refresh_when_resource_changes_detected"); iter != std::end(conn_pool)) {
		opts.refresh_connections_when_resource_changes_detected = iter->get<bool>();
	}

	return std::make_unique<irods::connection_pool>(
		conn_pool.at("size").get<int>(),
		client.at("host").get_ref<const std::string&>(),
		client.at("port").get<int>(),
		irods::experimental::fully_qualified_username{username, zone},
		irods::experimental::fully_qualified_username{username, zone},
		[pw = rodsadmin.at("password").get<std::string>()](RcComm& _comm) mutable {
			if (const auto ec = clientLoginWithPassword(&_comm, pw.data()); ec != 0) {
				throw std::invalid_argument{fmt::format("Could not authenticate rodsadmin user: [{}]", ec)};
			}
		},
		opts);
} // init_irods_connection_pool

auto load_oidc_configuration(const json& _config, json& _oi_config, json& _endpoint_config) -> void
{
	try {
		// Setup config
		_oi_config = _config.at(json::json_pointer{"/authentication/oidc"});
		irods::http::globals::set_oidc_configuration(_oi_config);

		// Consider reusing context further down main?
		net::io_context io_ctx;
		net::ip::tcp::resolver tcp_res{io_ctx};
		beast::tcp_stream tcp_stream{io_ctx};

		// Load config
		const auto host{_oi_config.at("config_host").get_ref<const std::string&>()};
		const auto port{std::to_string(_oi_config.at("port").get<int>())};
		const auto temp_uri{_oi_config.at("well_known_uri").get_ref<const std::string&>()};
		const auto uri{fmt::format("{}/.well-known/openid-configuration", temp_uri)};

		// Resolve addr
		const auto resolve{tcp_res.resolve(host, port)};

		// Connect and get config
		tcp_stream.connect(resolve);

		// Build Request
		constexpr auto version_number{11};
		beast::http::request<beast::http::string_body> req{beast::http::verb::get, uri, version_number};
		req.set(beast::http::field::host, host);
		req.set(beast::http::field::user_agent, irods::http::version::server_name);

		// Send request
		beast::http::write(tcp_stream, req);

		// Read back req
		beast::flat_buffer buffer;
		beast::http::response<beast::http::string_body> res;
		beast::http::read(tcp_stream, buffer, res);

		// TODO: Check resposnse code...
		log::debug("Got the following back: {}", res.body());

		// Convert http json response to nlomman json response
		_endpoint_config = json::parse(res.body());
		irods::http::globals::set_oidc_endpoint_configuration(_endpoint_config);

		// Close the socket
		beast::error_code ec;
		tcp_stream.socket().shutdown(net::ip::tcp::socket::shutdown_both, ec);
	}
	catch (const json::out_of_range& e) {
		log::trace("Invalid OIDC configuration, ignoring. Reason: {}", e.what());
	}
} // load_oidc_configuration

class process_stash_eviction_manager
{
	net::steady_timer timer_;
	std::chrono::seconds interval_;

  public:
	process_stash_eviction_manager(net::io_context& _io, std::chrono::seconds _eviction_check_interval)
		: timer_{_io}
		, interval_{_eviction_check_interval}
	{
		evict();
	} // constructor

  private:
	auto evict() -> void
	{
		timer_.expires_after(interval_);
		timer_.async_wait([this](const auto& _ec) {
			if (_ec) {
				return;
			}

			log::trace("Evicting expired items...");
			irods::http::process_stash::erase_if([](const auto& _k, const auto& _v) {
				// Check for client bearer token
				const auto* client_info{boost::any_cast<const irods::http::authenticated_client_info>(&_v)};
				const auto erase_token{(client_info && std::chrono::steady_clock::now() >= client_info->expires_at)};

				// Check for OAuth 2.0 state param
				const auto* expire_time{boost::any_cast<const std::chrono::steady_clock::time_point>(&_v)};
				const auto erase_state{(expire_time && std::chrono::steady_clock::now() >= *expire_time)};

				// Determine if value need to be deleted
				const auto erase_value{erase_token || erase_state};

				if (erase_token) {
					log::debug("Evicted bearer token [{}].", _k);
				}
				else if (erase_state) {
					log::debug("Evicted state [{}].", _k);
				}

				return erase_value;
			});

			evict();
		});
	} // evict
}; // class process_stash_eviction_manager

auto main(int _argc, char* _argv[]) -> int
{
	po::options_description opts_desc{""};

	// clang-format off
	opts_desc.add_options()
		("config-file,f", po::value<std::string>(), "")
		("dump-config-template", "")
		("help,h", "")
		("version,v", "");
	// clang-format on

	po::positional_options_description pod;
	pod.add("config-file", 1);

	set_ips_display_name("irods_http_api");

	try {
		po::variables_map vm;
		po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
		po::notify(vm);

		if (vm.count("help") > 0) {
			print_usage();
			return 0;
		}

		if (vm.count("version") > 0) {
			print_version_info();
			return 0;
		}

		if (vm.count("dump-config-template") > 0) {
			print_configuration_template();
			return 0;
		}

		if (vm.count("config-file") == 0) {
			fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
			return 1;
		}

		const auto config = json::parse(std::ifstream{vm["config-file"].as<std::string>()});
		irods::http::globals::set_configuration(config);

		const auto& http_server_config = config.at("http_server");
		set_log_level(http_server_config);
		spdlog::set_pattern("[%Y-%m-%d %T.%e] [P:%P] [%^%l%$] [T:%t] %v");

		log::info("Initializing server.");

		// Confirm OIDC endpoint is valid (Assume all provide endpoint)
		log::trace("Verifying OIDC endpoint configuration");

		// JSON configs needs to be in main scope to last the entire duration of the program
		nlohmann::json oi_config;
		nlohmann::json endpoint_config;
		load_oidc_configuration(http_server_config, oi_config, endpoint_config);

		// TODO For LONG running tasks, see the following:
		//
		//   - https://stackoverflow.com/questions/17648725/long-running-blocking-operations-in-boost-asio-handlers
		//   - https://www.open-std.org/JTC1/SC22/WG21/docs/papers/2012/n3388.pdf
		//

		log::trace("Loading API plugins.");
		load_client_api_plugins();

		const auto address = net::ip::make_address(http_server_config.at("host").get_ref<const std::string&>());
		const auto port = http_server_config.at("port").get<std::uint16_t>();
		const auto request_thread_count =
			std::max(http_server_config.at(json::json_pointer{"/requests/threads"}).get<int>(), 1);

		log::trace("Initializing TLS.");
		init_tls(config);

		std::unique_ptr<irods::connection_pool> conn_pool;

		if (!config.at(json::json_pointer{"/irods_client/enable_4_2_compatibility"}).get<bool>()) {
			log::trace("Initializing iRODS connection pool.");
			conn_pool = init_irods_connection_pool(config);
			irods::http::globals::set_connection_pool(*conn_pool);
		}

		// The io_context is required for all I/O.
		log::trace("Initializing HTTP components.");
		net::io_context ioc{request_thread_count};
		irods::http::globals::set_request_handler_io_context(ioc);

		// Create and launch a listening port.
		log::trace("Initializing listening socket (host=[{}], port=[{}]).", address.to_string(), port);
		std::make_shared<listener>(ioc, tcp::endpoint{address, port}, config)->run();

		// SIGINT and SIGTERM instruct the server to shut down.
		// Ignore SIGPIPE. The iRODS networking code assumes SIGPIPE is ignored or caught.
		log::trace("Initializing signal handlers.");
		net::signal_set signals{ioc, SIGINT, SIGTERM, SIGPIPE};

		const std::function<void(const beast::error_code&, int)> process_signals =
			[&ioc, &signals, &process_signals](const beast::error_code&, int _signal) {
				if (SIGPIPE == _signal) {
					signals.async_wait(process_signals);
					return;
				}

				// Stop the io_context. This will cause run() to return immediately, eventually destroying
			    // the io_context and all of the sockets in it.
				log::warn("Received signal [{}]. Shutting down.", _signal);
				ioc.stop();
			};

		signals.async_wait(process_signals);

		// Launch the requested number of dedicated backgroup I/O threads.
		// These threads are used for long running tasks (e.g. reading/writing bytes, database, etc.)
		log::trace("Initializing thread pool for long running I/O tasks.");
		net::thread_pool io_threads(
			std::max(http_server_config.at(json::json_pointer{"/background_io/threads"}).get<int>(), 1));
		irods::http::globals::set_background_thread_pool(io_threads);

		// Run the I/O service on the requested number of threads.
		log::trace("Initializing thread pool for HTTP requests.");
		net::thread_pool request_handler_threads(request_thread_count);
		for (auto i = request_thread_count - 1; i > 0; --i) {
			net::post(request_handler_threads, [&ioc] { ioc.run(); });
		}

		// Launch eviction check for expired bearer tokens.
		const auto eviction_check_interval =
			http_server_config.at(json::json_pointer{"/authentication/eviction_check_interval_in_seconds"}).get<int>();
		process_stash_eviction_manager eviction_mgr{ioc, std::chrono::seconds{eviction_check_interval}};

		log::info("Server is ready.");
		ioc.run();

		request_handler_threads.stop();
		io_threads.stop();

		log::trace("Waiting for HTTP requests thread pool to shut down.");
		request_handler_threads.join();

		log::trace("Waiting for I/O thread pool to shut down.");
		io_threads.join();

		log::info("Shutdown complete.");

		return 0;
	}
	catch (const irods::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.client_display_what());
	}
	catch (const std::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.what());
	}

	return 1;
} // main
