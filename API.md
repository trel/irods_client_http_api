# API Documentation

This document covers all endpoint operations.

If you discover that some topic related to the behavior of the endpoint operation isn't documented, please open an issue in the repository.

Throughout the document you'll come across identifiers such as `<version>`, `<string>`, `<integer>`, etc. These identifiers represent placeholders. Users are expected to replace placeholders with appropriate values.

## Authentication Operations

### Scheme: Basic

#### Request

```bash
curl -X POST -u <username>:<password> http://localhost:<port>/irods-http-api/<version>/authenticate
```

`<version>` must match the format, **X.Y.Z**, where **X** is the major version number, **Y** is the minor version number, and **Z** is the patch version number.

#### Response

A string representing a bearer token that can be used to execute operations as the authenticated user.

Tokens obtained via this authentication scheme have a finite lifetime. The lifetime of a token is defined in the configuration file at `/http_server/authentication/basic/timeout_in_seconds`. **Use of the token does NOT extend its lifetime**.

Attempting to use an expired or invalid token will result in a response containing a status code of **401 Unauthorized**. Checking for this status code is key to detecting when the client needs to reauthenticate.

Reauthentication can be performed at anytime and will result in a brand new token. This does NOT invalidate previously acquired tokens.

### Scheme: OpenID Connect (OIDC)

For authenticating with OpenID Connect, there are two methods:

- Resource Owner Password Credentials Grant
- Authorization Code Grant

#### Resource Owner Password Credentials Grant

The core advantage of this grant is the flexibility in how it may be applied.

Following is a brief example of authenticating from the command line.

##### Request
```bash
username_and_password=$(echo -n "<username>:<password>" | base64 -)
curl -X POST -H "Authorization: iRODS $username_and_password" \
    http://localhost:<port>/irods-http-api/<version>/authenticate
```

##### Response
A string representing a bearer token that can be used to execute operations as the authenticated user.

#### Authorization Code Grant

Using this grant requires a bit more work to extract the token.
Authentication is done in the browser.

##### Request
```bash
curl http://localhost:<port>/irods-http-api/<version>/authenticate -v
```

After running the previous command, you should see output similar to the following:
```
*   Trying [::1]:9000...
* Connected to localhost (::1) port 9000
> GET /irods-http-api/0.1.0/authenticate HTTP/1.1
> Host: localhost:9000
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 302 Found
< Server: irods_http_api/0.1.0 [d6164b7aa421265e0f9f9d5f7eb69bb67d8e4a3c]
< Location: http://oidc.example.org/realms/example/protocol/openid-connect/auth?...
< Content-Length: 0
< 
* Connection #0 to host localhost left intact
```

To authenticate, you need to head to the `Location` provided in the response.
This will open a browser window that will allow you to authenticate in.

##### Response
The bearer token should be returned and viewable in the browser window after authenticating.

## Collection Operations

### create

Creates a new collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'create-intermediates=<integer>' # 0 or 1. Defaults to 0.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "created": false // Conditionally available. Check "irods_response/status_code" first.
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove

Removes a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'recurse=<integer>' \ # 0 or 1. Defaults to 0.
    --data-urlencode 'no-trash=<integer>' # 0 or 1. Defaults to 0.
```

If `recurse` is set to 1, the contents of the collection will be removed. If `no-trash` is set to 1, the collection is permanently removed.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### stat

Returns information about a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'ticket=<string>' \ # Optional.
    -G
```

If `ticket` is passed a valid ticket string, it will be enabled before carrying out the operation.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "type": "string",
    "inheritance_enabled": false,
    "permissions": [
        {
            "name": "string",
            "zone": "string",
            "type": "string",
            "perm": "string"
        }
    ],
    "registered": false,
    "modified_at": 0
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### list

Returns the contents of a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=list' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'recurse=<integer>' \ # 0 or 1. Defaults to 0.
    --data-urlencode 'ticket=<string>' \ # Optional
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "entries": [
        "string",
        "string",
        "string"
    ]
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### set_permission

Sets the permission of a user or group on a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'entity-name=<string>' \ # The name of a user or group.
    --data-urlencode 'permission=<string>' \ # null, read, write, or own.
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### modify_permissions

Adjust permissions for multiple users and groups on a collection atomically.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_permissions' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'operations=<json_object>' \
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "entity_name": "string", // The name of a user or group.
        "acl": "string" // null, read, write, or own.
    },

    // Additional ACL operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "entity_name": "string", // The name of a user or group.
                "acl": "string" // null, read, write, or own.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

### modify_metadata

Adjust multiple AVUs on a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_metadata' \
    --data-urlencode 'lpath=<string>' \
    --data-urlencode 'operations=<json_object>' \
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0.
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "operation": "string", // add or remove.
        "attribute": "string",
        "value": "string",
        "units": "string" // Optional.
    },

    // Additional AVU operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "operation": "string", // add or remove.
                "attribute": "string",
                "value": "string",
                "units": "string" // Optional.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

### rename

Renames or moves a collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=<string>' \
    --data-urlencode 'new-lpath=<string>'
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### touch

Updates the mtime of an existing collection.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=touch' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a collection.
    --data-urlencode 'seconds-since-epoch=<integer>' \ # The mtime to assign to the collection. Optional.
    --data-urlencode 'reference=<string>' # The absolute logical path of an object whose mtime will be copied to the collection. Optional.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

## Data Object Operations

### touch

Updates the mtime of an existing data object or creates a new data object if it does not exist.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=touch' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'no-create=<integer>' \ # 0 or 1. Defaults to 0. If set to 1, no data objects will be created.
    --data-urlencode 'replica-number=<integer>' \ # The replica to update. The replica must exist. Optional.
    --data-urlencode 'leaf-resource=<string>' \ # The resource holding an existing replica. If it does not exist, it will be created on the specified resource. Optional.
    --data-urlencode 'seconds-since-epoch=<integer>' \ # The mtime to assign to the replica. Optional.
    --data-urlencode 'reference=<string>' # The absolute logical path of an object whose mtime will be copied to the data object. Optional.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove

Removes a data object.

The data object will be permanently deleted if `no-trash=1` is passed.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'no-trash=<integer>' \ # 0 or 1. Defaults to 0. If set to 1, permanently deletes the data object.
    --data-urlencode 'unregister=<integer>' # 0 or 1. Defaults to 0. Removes only the catalog entry.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### calculate_checksum

Calculates the checksum for a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=calculate_checksum' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'resource=<string>' \ # The resource holding the target replica. Optional.
    --data-urlencode 'replica-number=<integer>' \ # The replica number of the target replica. Optional.
    --data-urlencode 'force=<integer>' \ # 0 or 1. Defaults to 0. Overwrite the existing checksum.
    --data-urlencode 'all=<integer>' \ # 0 or 1. Defaults to 0. Calculate checksums for all replicas.
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

`resource`, `replica-number`, and `all` are mutually exclusive parameters.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "checksum": "string"
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### verify_checksum

Verifies the checksum information for a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=verify_checksum' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'resource=<string>' \ # The resource holding the target replica. Optional.
    --data-urlencode 'replica-number=<integer>' \ # The replica number of the target replica. Optional.
    --data-urlencode 'compute-checksums=<integer>' \ # 0 or 1. Defaults to 1. Can be used to skip the checksum calculation step.
    --data-urlencode 'admin=<integer>' \ # 0 or 1. Defaults to 0. Execute as a rodsadmin.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "results": {
        // Verification results. This object only exists if the operation found inconsistencies
        // between what's in storage and what's in the catalog.
    },
    "r_error_info": [
        {
            "status": 0,
            "message": "string"
        },

        // Additional elements ...
    ]
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### stat

Returns information about a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'ticket=<string>' \ # The ticket to enable before stat'ing the data object. Optional.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "type": "string",
    "permissions": [
        {
            "name": "string",
            "zone": "string",
            "type": "string",
            "perm": "string"
        }
    ],
    "size": 0,
    "checksum": "string",
    "registered": false,
    "modified_at": 0
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### rename

Renames or moves a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=<string>' \ # The absolute logical path of the data object to rename.
    --data-urlencode 'new-lpath=<string>' # The new absolute logical path of the data object.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### copy

Copies a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=copy' \
    --data-urlencode 'src-lpath=<string>' \ # The absolute logical path of the data object to copy.
    --data-urlencode 'dst-lpath=<string>' \ # The absolute logical path of the new data object.
    --data-urlencode 'options=<string>' # skip_existing, overwrite_existing, update_existing, none. Defaults to none.
```

The `options` parameter may not be implemented.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "copied": false
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### replicate

Replicates an existing replica from one resource to another resource.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=replicate' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'src-resource=<string>' \ # The resource to replicate from.
    --data-urlencode 'dst-resource=<string>' \ # The resource to replicate to.
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### trim

Trims an existing replica.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=trim' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'resource=<string>' \ # Name of the resource to trim from.
    --data-urlencode 'replica-number=<integer>' \ # The replica number identifying the replica to trim.
    --data-urlencode 'unregister=<integer>' \ # 0 or 1. Optional. Instructs the server to only remove the catalog entry.
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

`resource` and `replica-number` are mutually exclusive parameters. At least one of them MUST be included in the request.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### register

Registers a new data object and/or replica into the catalog.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=register' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'ppath=<string>' \ # Absolute physical path to file on the iRODS server.
    --data-urlencode 'resource=<string>' \ # The resource which will own the replica.
    --data-urlencode 'as-additional-replica=<integer>' \ # 0 or 1. Defaults to 0. Register as an additional replica for an existing data object.
    --data-urlencode 'data-size=<integer>' \ # The size of the replica in bytes. Optional.
    --data-urlencode 'checksum=<string>' \ # The checksum to associate with the replica. Optional.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### read

Reads bytes from a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=read' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'offset=<integer>' \ # Number of bytes to skip. Defaults to 0.
    --data-urlencode 'count=<integer>' \ # Number of bytes to read.
    --data-urlencode 'ticket=<string>' \ # The ticket to enable before reading the data object. Optional.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain the bytes read from the data object.

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### write

Writes bytes to a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    [-F,--data-urlencode] 'op=write' \
    [-F,--data-urlencode] 'lpath=<string>' \ # Absolute logical path to a data object.
    [-F,--data-urlencode] 'resource=<string>' \ # The root resource to write to. Optional.
    [-F,--data-urlencode] 'offset=<integer>' \ # Number of bytes to skip. Defaults to 0.
    [-F,--data-urlencode] 'count=<integer>' \ # Number of bytes to write.
    [-F,--data-urlencode] 'truncate=<integer>' \ # 0 or 1. Defaults to 1. Truncates the data object before writing.
    [-F,--data-urlencode] 'append=<integer>' \ # 0 or 1. Defaults to 0. Appends the bytes to the data object.
    [-F,--data-urlencode] 'bytes=<binary_data>;type=application/octet-stream' \ # The bytes to write.
    [-F,--data-urlencode] 'parallel-write-handle=<string>' \ # The handle to use when writing in parallel. Optional.
    [-F,--data-urlencode] 'stream-index=<integer>' # The stream to use when writing in parallel. Optional.
```

This is the full set of parameters supported by the operation.

When sending large amounts of data or writing in parallel, prefer multipart/form-data over application/x-www-form-urlencoded as the Content-Type.

`parallel-write-handle` and `stream-index` only apply when writing to a replica in parallel. To obtain a parallel-write-handle, see [parallel_write_init](#parallel_write_init).

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain the bytes read from the data object.

```
{
    "irods_response": {
        "status_code": 0,
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### parallel_write_init

Initializes server-side state used for writing to a data object in parallel.

Returns a parallel-write-handle that can be used for parallel write operations.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=parallel_write_init' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'stream-count=<integer>' \ # Number of streams to open.
    --data-urlencode 'truncate=<integer>' \ # 0 or 1. Defaults to 1. Truncates the data object before writing.
    --data-urlencode 'append=<integer>' \ # 0 or 1. Defaults to 0. Appends the bytes to the data object.
    --data-urlencode 'ticket=<string>' # The ticket to enable for all streams. Optional.
```

#### Response

```
{
    "irods_response": {
        "status_code": 0,
        "status_message": "string" // Optional
    },
    "parallel_write_handle": "string"
}
```

### parallel_write_shutdown

Instructs the server to shutdown and release any resources used for parallel write operations.

This operation MUST be called to complete the parallel write operation. Failing to call this operation will result in intermediate replicas and the server leaking memory.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=parallel_write_shutdown' \
    --data-urlencode 'parallel-write-handle=<string>' # A handle obtained via the parallel_write_init operation.
```

#### Response

```
{
    "irods_response": {
        "status_code": 0,
        "status_message": "string" // Optional
    }
}
```

### modify_metadata

Adjust multiple AVUs on a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_metadata' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'operations=<json_object>' \
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "operation": "string", // add or remove.
        "attribute": "string",
        "value": "string",
        "units": "string" // Optional.
    },

    // Additional AVU operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "operation": "string", // add or remove.
                "attribute": "string",
                "value": "string",
                "units": "string" // Optional.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

### set_permission

Sets the permission of a user or group on a data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'entity-name=<string>' \ # The name of a user or group.
    --data-urlencode 'permission=<string>' \ # null, read, write, or own.
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### modify_permissions

Adjust permissions for multiple users and groups on a data object atomically.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_permissions' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'operations=<json_object>' \
    --data-urlencode 'admin=<integer>' # 0 or 1. Defaults to 0. Execute as a rodsadmin.
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "entity_name": "string", // The name of a user or group.
        "acl": "string" // null, read, write, or own.
    },

    // Additional ACL operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "entity_name": "string", // The name of a user or group.
                "acl": "string" // null, read, write, or own.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

### modify_replica

Modifies properties of a single replica.

**WARNING:** This operation requires rodsadmin level privileges and should only be used when there isn't a safer option. Misuse can lead to catalog inconsistencies and unexpected behavior.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_replica' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object.
    --data-urlencode 'resource-hierarchy=<string>' \
    --data-urlencode 'replica-number=<integer>' \
    --data-urlencode 'new-data-checksum=<string>' \
    --data-urlencode 'new-data-comments=<string>' \
    --data-urlencode 'new-data-create-time=<integer>' \
    --data-urlencode 'new-data-expiry=<integer>' \
    --data-urlencode 'new-data-mode=<string>' \
    --data-urlencode 'new-data-modify-time=<string>' \
    --data-urlencode 'new-data-path=<string>' \
    --data-urlencode 'new-data-replica-number=<integer>' \
    --data-urlencode 'new-data-replica-status=<integer>' \
    --data-urlencode 'new-data-resource-id=<integer>' \
    --data-urlencode 'new-data-size=<integer>' \
    --data-urlencode 'new-data-status=<string>' \
    --data-urlencode 'new-data-type-name=<string>' \
    --data-urlencode 'new-data-version=<string>'
```

`resource-hierarchy` and `replica-number` are mutually exclusive parameters.

All parameters having a prefix of `new-` represent modifiable properties of the target replica. At least one modifiable property is required for the operation to succeed.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

## Information Operations

Returns general information about the iRODS HTTP API server.

### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/info
```

### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "api_version": "string",
    "build": "string",
    "genquery2_enabled": false,
    "irods_zone": "string",
    "max_http_request_size_in_bytes": 0,
    "max_number_of_parallel_write_streams": 0,
    "max_number_of_rows_per_catalog_query": 0
}
```

## Query Operations

### execute_genquery

Executes a GenQuery string and returns the results.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/query \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute_genquery' \
    --data-urlencode 'query=<string>' \
    --data-urlencode 'offset=<integer>' \ # Number of rows to skip. Defaults to 0.
    --data-urlencode 'count=<integer>' \ # Number of rows to return. Default set by administrator.
    --data-urlencode 'case-sensitive=<integer>' \ # Execute a case sensitive/insensitive query. Defaults to 1. Only supported by GenQuery1.
    --data-urlencode 'distinct=<integer>' \ # Collapse duplicate rows. Defaults to 1. Only supported by GenQuery1.
    --data-urlencode 'parser=<string>' \ # genquery1 or genquery2. Defaults to genquery1.
    --data-urlencode 'sql-only=<integer>' \ # 0 or 1. Defaults to 0. Only supported by GenQuery2.
    --data-urlencode 'zone=<string>' \ # The zone name. Defaults to the local zone.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "rows": [
        ["string", "string", "string"],

        // Additional rows ...
    ],
    "sql": "string" // If "sql-only" option is set to 1.
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### execute_specific_query

Executes a specific query and returns the results.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/query \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute_specific_query' \
    --data-urlencode 'name=<string>' \ # Name of specific query.
    --data-urlencode 'args=<string>' \ # List of arguments.
    --data-urlencode 'args-delimiter=<string>' \ # Delimiter used to separate arguments. Defaults to comma (,).
    --data-urlencode 'offset=<integer>' \ # Number of rows to skip. Defaults to 0.
    --data-urlencode 'count=<integer>' \ # Number of rows to return. Default set by administrator.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "rows": [
        ["string", "string", "string"],

        // Additional rows ...
    ]
}
```

## Resource Operations

### create

Creates a new resource.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'name=<string>' \ # Name of the resource.
    --data-urlencode 'type=<string>' \ # Type of the resource.
    --data-urlencode 'host=<string>' \ # Depends on the resource's type. May be required.
    --data-urlencode 'vault-path=<string>' \ # Depends on the resource's type. May be required.
    --data-urlencode 'context=<string>' # Depends on the resource's type. May be required.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove

Removes a resource.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=<string>' # Name of the resource.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### add_child

Creates a parent-child relationship between two resources.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=add_child' \
    --data-urlencode 'parent-name=<string>' \
    --data-urlencode 'child-name=<string>' \
    --data-urlencode 'context=<string>' # Additional information for the zone. Optional.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove_child

Removes the parent-child relationship between two resources.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_child' \
    --data-urlencode 'parent-name=<string>' \
    --data-urlencode 'child-name=<string>'
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### rebalance

Rebalances a resource hierarchy.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rebalance' \
    --data-urlencode 'name=<string>'
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### stat

Returns information about a resource.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'name=<string>' \
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "exists": false,
    "info": {
        "id": "string",
        "name": "string",
        "type": "string",
        "zone": "string",
        "host": "string",
        "vault_path": "string",
        "status": "string",
        "context": "string",
        "comments": "string",
        "information": "string",
        "free_space": "string",
        "free_space_last_modified": 0,
        "parent_id": "string",
        "created": 0,
        "last_modified": 0,
        "last_modified_millis": 0
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### modify_metadata

Adjust multiple AVUs on a resource.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_metadata' \
    --data-urlencode 'name=<string>' \
    --data-urlencode 'operations=<json_object>'
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "operation": "string", // add or remove.
        "attribute": "string",
        "value": "string",
        "units": "string" // Optional.
    },

    // Additional AVU operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "operation": "string", // add or remove.
                "attribute": "string",
                "value": "string",
                "units": "string" // Optional.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

## Rule Operations

### list_rule_engines

Lists the available rule engine plugin instances of the connected iRODS server.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=list_rule_engines' \
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "rule_engine_plugin_instances": [
        "string",
        "string",
        "string"
    ]
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### execute

Executes rule code.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute' \
    --data-urlencode 'rule-text=<string>' \ # The rule code to execute.
    --data-urlencode 'rep-instance=<string>' # The rule engine plugin to run the rule-text against. Optional.
```

If `rep-instance` is not passed, the rule text will be tried on ALL rule engine plugins. Any errors that occur will be ignored. Setting `rep-instance` is highly recommended.

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "stdout": "string",
    "stderr": "string"
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove_delay_rule

Removes a delay rule from the catalog.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_delay_rule' \
    --data-urlencode 'rule-id=<integer>' # The ID of delay rule to remove.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

## Ticket Operations

### create

Creates a new ticket for a collection or data object.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/tickets \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=<string>' \ # Absolute logical path to a data object or collection.
    --data-urlencode 'type=<string>' \ # read or write. Defaults to read.
    --data-urlencode 'use-count=<integer>' \ # Number of times the ticket can be used. Optional.
    --data-urlencode 'write-data-object-count=<integer>' \ # Max number of writes that can be performed. Optional.
    --data-urlencode 'write-byte-count=<integer>' \ # Max number of bytes that can be written. Optional.
    --data-urlencode 'seconds-until-expiration=<integer>' \ # Number of seconds before the ticket expires. Optional.
    --data-urlencode 'users=<string>' \ # Comma-delimited list of users allowed to use the ticket. Optional.
    --data-urlencode 'groups=<string>' \ # Comma-delimited list of groups allowed to use the ticket. Optional.
    --data-urlencode 'hosts=<string>' # Comma-delimited list of hosts allowed to use the ticket. Optional.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "ticket": "string" // The generated ticket string.
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove

Removes a ticket.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/tickets \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=<string>' # The ticket string.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

## User and Group Operations

### create_user

Creates a new user.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create_user' \
    --data-urlencode 'name=<string>' \ # Name of user.
    --data-urlencode 'zone=<string>' \ # Name of zone for user.
    --data-urlencode 'user-type=<string>' # rodsuser, groupadmin, or rodsadmin. Defaults to rodsuser.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove_user

Removes a user.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_user' \
    --data-urlencode 'name=<string>' \ # Name of user.
    --data-urlencode 'zone=<string>' # Name of zone for user.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### set_password

Changes a user's password.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_password' \
    --data-urlencode 'name=<string>' \ # Name of user.
    --data-urlencode 'zone=<string>' \ # Name of zone for user.
    --data-urlencode 'new-password=<string>'
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### set_user_type

Changes a user's type.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_user_type' \
    --data-urlencode 'name=<string>' \ # Name of user.
    --data-urlencode 'zone=<string>' \ # Name of zone for user.
    --data-urlencode 'new-user-type=<string>' # rodsuser, groupadmin, or rodsadmin.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### create_group

Creates a new group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create_group' \
    --data-urlencode 'name=<string>' # Name of the group.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove_group

Removes a group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_group' \
    --data-urlencode 'name=<string>' # Name of the group.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### add_to_group

Adds a user to a group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=add_to_group' \
    --data-urlencode 'user=<string>' # Name of the user.
    --data-urlencode 'zone=<string>' # Name of zone for the user.
    --data-urlencode 'group=<string>' # Name of the group.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### remove_from_group

Removes a user from a group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_from_group' \
    --data-urlencode 'user=<string>' # Name of the user.
    --data-urlencode 'zone=<string>' # Name of zone for the user.
    --data-urlencode 'group=<string>' # Name of the group.
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### users

Lists all users in the zone.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=users' \
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "users": [
        {
            "name": "string",
            "zone": "string"
        },

        // Additional users.
    ]
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### groups

Lists all groups in the zone.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=groups' \
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "groups": [
        "string",
        "string",
        "string"
    ]
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### is_member_of_group

Returns whether a user is a member of a group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=is_member_of_group' \
    --data-urlencode 'group=<string>' \ # Name of the group.
    --data-urlencode 'user=<string>' \ # Name of the user.
    --data-urlencode 'zone=<string>' \ # Name of zone for the user.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "is_member": false
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### stat

Returns information about a user or group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'name=<string>' \ # Name of a user or group.
    --data-urlencode 'zone=<string>' \ # Name of zone if name represents a user. Not required for groups.
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "exists": false,
    "id": "string",
    "local_unique_name": "string",
    "type": "string"
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.

### modify_metadata

Adjust multiple AVUs on a user or group.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify_metadata' \
    --data-urlencode 'name=<string>' \
    --data-urlencode 'operations=<json_object>'
```

The JSON object passed to the `operations` parameter must have the following structure:

```js
[
    {
        "operation": "string", // add or remove.
        "attribute": "string",
        "value": "string",
        "units": "string" // Optional.
    },

    // Additional AVU operations ...
]
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range. If an operation failed, the `irods_response` object will include an additional property called `failed_operation`. The structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string", // Optional
        "failed_operation": {
            "operation": {
                "operation": "string", // add or remove.
                "attribute": "string",
                "value": "string",
                "units": "string" // Optional.
            },
            "operation_index": 0,
            "status_message": "string"
        }
    }
}
```

## Zone Operations

### report

Returns information about the iRODS zone.

#### Request

```bash
curl http://localhost:<port>/irods-http-api/<version>/zones \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=report' \
    -G
```

#### Response

If an HTTP status code of 200 is returned, the body of the response will contain JSON. Its structure is shown below.

```js
{
    "irods_response": {
        "status_code": 0
        "status_message": "string" // Optional
    },
    "zone_report": {
        // Equivalent output of executing izonereport.
    }
}
```

If there was an error, expect an HTTP status code in either the 4XX or 5XX range.
