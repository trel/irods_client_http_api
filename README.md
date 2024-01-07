# iRODS HTTP API

A project that presents an iRODS Zone as HTTP v1.1.

## Quickstart (Running from Docker Hub Image)

Generate a local configuration JSON file.

```
docker run --rm irods/irods_http_api --dump-config-template > config.json
```

Edit/update the template `config.json` file (point to your iRODS Zone, remove OIDC and TLS sections, etc.).

```
vim config.json
```

Launch the HTTP API with your customized configuration file to check for success/errors.

```
docker run --rm --name irods_http_api \
    -v ./config.json:/config.json:ro \
    -p 9000:9000 \
    irods/irods_http_api
```

Then, the HTTP API will be available.

```
$ curl -X POST -u rods:rods \
 http://localhost:9000/irods-http-api/0.1.0/authenticate
568bbfc2-7d19-4723-b659-bb9325f9b076

$ curl -s http://localhost:9000/irods-http-api/0.1.0/collections \
    -H 'Authorization: Bearer 568bbfc2-7d19-4723-b659-bb9325f9b076' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=/tempZone/home/rods' -G | jq
{
  "inheritance_enabled": false,
  "irods_response": {
    "status_code": 0
  },
  "modified_at": 1699448576,
  "permissions": [
    {
      "name": "rods",
      "perm": "own",
      "type": "rodsadmin",
      "zone": "tempZone"
    },
    {
      "name": "alice",
      "perm": "read_object",
      "type": "groupadmin",
      "zone": "tempZone"
    }
  ],
  "registered": true,
  "type": "collection"
}
```

## Documentation

API documentation can be found in [API.md](./API.md).

## Build Dependencies

- iRODS development package
- iRODS externals package for boost
- iRODS externals package for nlohmann-json
- iRODS externals package for spdlog 
- Curl development package
- OpenSSL development package
- GenQuery2 package (optional)

## Build

This project can be built with or without support for [GenQuery2](https://github.com/irods/irods_api_plugin_genquery2).

GenQuery2 is disabled by default.

### Building without GenQuery2

If you don't need support for GenQuery2, follow the normal CMake steps.

```bash
mkdir build # Preferably outside of the repository
cd build
cmake /path/to/repository
make package # Use -j to use more parallelism.
```

Upon success, you should have an installable package.

### Building with GenQuery2

To build with GenQuery2 enabled, the HTTP API needs access to files only provided by the GenQuery2 package.

If you haven't already done so, install the GenQuery2 package. See the [GenQuery2](https://github.com/irods/irods_api_plugin_genquery2) repository for details on how to do that.

Now, run the following steps to produce an installable package.

```bash
mkdir build # Preferably outside of the repository
cd build
cmake -DIRODS_ENABLE_GENQUERY2=YES /path/to/repository
make package # Use -j to use more parallelism.
```

Keep in mind that even though you've compiled the HTTP API with support for GenQuery2, that is half the story. You must also install the GenQuery2 package on the iRODS server which the HTTP API will connect to and the iRODS Catalog Service Provider.

## Docker

This project provides two Dockerfiles, one for building and one for running the application. GenQuery2 is enabled by default. As mentioned in the previous section, the iRODS server must have GenQuery2 installed before attempting to use the parser.

**IMPORTANT: All commands in the sections that follow assume you are located in the root of the repository.**

### The Builder Image

The builder image is responsible for building the iRODS HTTP API package. Before you can use it, you must build the image. To do that, run the following:
```bash
docker build -t irods-http-api-builder \
    -f irods_builder.Dockerfile .
```

With the builder image in hand, all that's left is to get the source code for the GenQuery2 project and HTTP API project. The builder image is designed to compile code sitting on your machine. This is important because it gives you the ability to build any fork or branch of the projects.

Building the packages requires mounting the projects into the container at the appropriate locations. The command you run should look similar to the one below. Don't forget to create the directory which will hold your packages!
```bash
docker run -it --rm \
    -v /path/to/irods_api_plugin_genquery2:/genquery2_source:ro \
    -v /path/to/irods_client_http_api:/http_api_source:ro \
    -v /path/to/packages_directory:/packages_output \
    irods-http-api-builder
```

If everything succeeds, you will have two DEB packages in the local directory you mapped to **/packages_output**.

### The Runner Image

The runner image is responsible for running the iRODS HTTP API. Building the runner image requires the DEB packages for GenQuery2 and the iRODS HTTP API to exist on the local machine. See the previous section for details on generating the packages.

To build the image, run the following command:
```bash
docker build -t irods-http-api-runner \
    -f irods_runner.Dockerfile \
    /path/to/packages/directory
```

If all goes well, you will have a containerized iRODS HTTP API server! You can verify this by checking the version information. Below is an example.
```bash
$ docker run -it --rm irods-http-api-runner -v
irods_http_api v0.1.0-f6f6411
```

### Launching the Container

To run the containerized server, you need to provide a configuration file at the correct location. If you do not have a configuration file already, see [Configuration](#configuration) for details.

Assuming you have a valid configuration file, you can launch the server by running the following command:
```bash
docker run -d --rm --name irods_http_api \
    -v /path/to/config/file:/config.json:ro \
    -p 9000:9000 \
    irods-http-api-runner
```

You can view the log output using `docker logs -f` or by passing `-it` to `docker run` instead of `-d`.

Congratulations, you now have a working iRODS HTTP API server!

#### Validating the Configuration

If you have Python 3 and the jsonschema module installed, you can validate your configuration on startup. To do that, launch the container with `--jsonschema-file`. Below is an example.
```bash
docker run -d --rm --name irods_http_api \
    -v /path/to/config/file:/config.json:ro \
    -p 9000:9000 \
    irods-http-api-runner \
    --jsonschema-file
```

If your configuration passes validation, the server will start. Otherwise, the server will print the validation results to the terminal and exit.

If for some reason the default schema file is not sufficient, you can instruct the iRODS HTTP API to use a different file. See the following example.
```bash
# Generate the default JSON schema.
docker run -it --rm irods-http-api-runner --dump-jsonschema > schema.json

# Tweak the schema.
vim schema.json

# Launch the server with the new schema file.
docker run -d --rm --name irods_http_api \
    -v /path/to/config/file:/config.json:ro \
    -v ./schema.json:/jsonschema.json:ro \
    -p 9000:9000 \
    irods-http-api-runner \
    --jsonschema-file /jsonschema.json
```

### Stopping the Container

If the container was launched with `-it`, use **CTRL-C** or `docker container stop <container_name>` to shut it down.

If the container was launched with `-d`, use `docker container stop <container_name>`.

## Configuration

Before you can run the server, you'll need to create a configuration file.

You can generate a configuration file by running the following:
```bash
irods_http_api --dump-config-template > config.json
```

**IMPORTANT: `--dump-config-template` does not produce a fully working configuration. It must be updated before it can be used.**

### Configuration File Structure

The JSON structure below represents the default configuration.

Notice how some of the configuration values are wrapped in angle brackets (e.g. `"<string>"`). These are placeholder values that must be updated before launch.

**IMPORTANT: The comments in the JSON structure are there for explanatory purposes and must not be included in your configuration. Failing to follow this requirement will result in the server failing to start up.**

```js
{
    // Defines HTTP options that affect how the client-facing component of the
    // server behaves.
    "http_server": {
        // The hostname or IP address to bind.
        // "0.0.0.0" instructs the server to listen on all network interfaces.
        "host": "0.0.0.0",

        // The port used to accept incoming client requests.
        "port": 9000,

        // The minimum log level needed before logging activity.
        //
        // The following values are supported:
        // - trace
        // - debug
        // - info
        // - warn
        // - error
        // - critical
        "log_level": "info",

        // Defines options that affect various authentication schemes.
        "authentication": {
            // The amount of time that must pass before checking for expired
            // bearer tokens.
            "eviction_check_interval_in_seconds": 60,

            // Defines options for the "Basic" authentication scheme.
            "basic": {
                // The amount of time before a user's "Basic" authentication
                // token expires.
                "timeout_in_seconds": 3600
            },

            // Defines required OIDC related configuration.
            "oidc": {
                // The hostname or ip address of the OIDC provider.
                "config_host": "oidc.example.org",

                // The port the OIDC provider is listening on.
                "port": 8080,

                // Well known endpoint to retrieve configuration of OIDC provider.
                "well_known_uri": "/realms/example",

                // The client id given to the application by OIDC provider.
                "client_id": "irods_http_api",

                // URI pointing to the irods HTTP API auth endpoint.
                "redirect_uri": "https://<domain>/irods-http/0.1.0/authenticate",

                // The amount of time before the OIDC Authorization Code grant
                // times out, requiring another attempt at authentication.
                "state_timeout_in_seconds": 600
            }
        },

        // Defines options that affect how client requests are handled.
        "requests": {
            // The number of threads dedicated to servicing client requests.
            // When adjusting this value, consider adjusting "background_io/threads"
            // and "irods_client/connection_pool/size" as well.
            "threads": 3,

            // The maximum size allowed for the body of a request.
            "max_size_of_body_in_bytes": 8388608,

            // The amount of time allowed to service a request. If the timeout
            // is exceeded, the client's connection is terminated immediately.
            "timeout_in_seconds": 30
        },

        // Defines options that affect tasks running in the background.
        // These options are primarily related to long-running tasks.
        "background_io": {
            // The number of threads dedicated to background I/O.
            "threads": 6
        }
    },

    // Defines iRODS connection information.
    "irods_client": {
        // The hostname or IP of the target iRODS server.
        "host": "<string>",

        // The port of the target iRODS server.
        "port": 1247,

        // The zone of the target iRODS server.
        "zone": "<string>",

        // Defines options for secure communication with the target iRODS server.
        "tls": {
            // Controls whether the client and server communicate using TLS.
            //
            // The following values are supported:
            // - CS_NEG_REFUSE:    Do not use secure communication.
            // - CS_NEG_REQUIRE:   Demand secure communication.
            // - CS_NEG_DONT_CARE: Let the server decide.
            "client_server_policy": "CS_NEG_REFUSE",

            // The file containing trusted CA certificates in PEM format.
            //
            // Note that the certificates in this file are used in conjunction
            // with the system default trusted certificates.
            "ca_certificate_file": "<string>",

            // The file containing the server's certificate chain.
            //
            // The certificates must be in PEM format and must be sorted
            // starting with the subject's certificate (actual client or server
            // certificate), followed by intermediate CA certificates if
            // applicable, and ending at the highest level (root) CA.
            "certificate_chain_file": "<string>",

            // The file containing Diffie-Hellman parameters.
            "dh_params_file": "<string>",

            // Defines the level of server certificate authentication to
            // perform.
            //
            // The following values are supported:
            // - none:     Authentication is skipped.
            // - cert:     The server verifies the certificate is signed by
            //             a trusted CA.
            // - hostname: Equivalent to "cert", but also verifies the FQDN
            //             of the iRODS server matches either the common
            //             name or one of the subjectAltNames.
            "verify_server": "cert"
        },

        // Controls how the HTTP API communicates with the iRODS server.
        //
        // When set to true, the following applies:
        // - Only APIs supported by the iRODS 4.2 series will be used.
        // - Connection pool settings are ignored.
        // - All HTTP requests will be served using a new iRODS connection.
        //
        // When set to false, the HTTP API will take full advantage of the
        // iRODS server's capabilities.
        //
        // This option should be used when the HTTP API is configured to
        // communicate with an iRODS 4.2 server.
        "enable_4_2_compatibility": false,

        // The credentials for the rodsadmin user that will act as a proxy
        // for all authenticated users.
        "proxy_admin_account": {
            "username": "<string>",
            "password": "<string>"
        },

        // Defines options for the connection pool.
        "connection_pool": {
            // The number of connections in the pool.
            "size": 6,

            // The amount of time that must pass before a connection is
            // renewed (i.e. replaced).
            "refresh_timeout_in_seconds": 600,

            // The number of times a connection can be fetched from the pool
            // before it is refreshed.
            "max_retrievals_before_refresh": 16,

            // Instructs the connection pool to track changes in resources.
            // If a change is detected, all connections will be refreshed.
            "refresh_when_resource_changes_detected": true
        },

        // The maximum number of parallel streams that can be associated to a
        // single parallel write handle.
        "max_number_of_parallel_write_streams": 3,

        // The maximum number of bytes that can be read from a data object
        // during a single read operation.
        "max_number_of_bytes_per_read_operation": 8192,

        // The buffer size used for write operations.
        "buffer_size_in_bytes_for_write_operations": 8192,

        // The number of rows that can be returned by a General or Specific
        // query. If the client specifies a number greater than the value
        // defined here, it will be clamped to this value. If the client does
        // not specify a value, it will be defaulted to this value.
        "max_number_of_rows_per_catalog_query": 15
    }
}
```

## Run

To run the server, do the following:
```bash
irods_http_api /path/to/config.json
```

To stop the server, you can use **CTRL-C** or send **SIGINT** or **SIGTERM** to the process.

### OpenID Connect
Some additional configuration is required to run the OpenID Connect portion of the HTTP API.
Following are a few points of interest.

#### OpenID Provider Requirements and HTTP API Configuration
The OpenID Provider, at this moment, must support discovery via a well-known endpoint.
This endpoint must be specified in the `well_known_uri` OIDC configuration parameter.

One should take care to ensure that `/.well-known/openid-configuration` is not included
in the configuration parameter, as this is included automatically.

One must also set the OIDC `config_host` and `port` parameter, so that the OpenID configuration
may be gathered from the well-known endpoint on the HTTP API server's startup.
The OpenID Provider must be running prior to starting the HTTP API server, otherwise, the HTTP API server
will not be able to query the required information from the desired OpenID Provider.

Additionally, the OIDC `redirect_uri` parameter must be set to the HTTP API's authentication endpoint.
This is required, as the Authorization Code Grant needs to be redirected back to the HTTP API, to complete
HTTP API token generation.

#### Add `irods_username` to the claims
Currently, the server looks for the custom claim `irods_username` in the ID Token.
This serves as the mapping mechanism for an OIDC User to an iRODS User.

A user who authenticates but does not have a `irods_username` mapped in their account
will not have access to the API.
A HTTP 400 Bad Request status code will be returned if no `irods_username` is found.

#### Supported Grants
Currently, the HTTP API server supports the following two grants:

- Resource Owner Password Credentials Grant
- Authorization Code Grant

While we currently support the _Resource Owner Password Credentials Grant_, there are plans to remove
support for this in the future.

Reason being, the [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) draft,
as well as the [The OAuth 2.1 Authorizaiton Framework](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) draft both deprecate that grant.
More information can be found on the reasoning for the deprecation in the links provided above.
