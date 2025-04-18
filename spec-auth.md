# SBD Auth Spec

This is an augmentation to the SBD Spec (spec.md), providing an authentication hook mechanism.

## Addition of REST API to SBD Web Server

The SBD webserver will be augmented to include the following HTTP REST endpoint in addition to the websocket service currently provided.

- `PUT /authenticate`
  - Required Request Header: `Content-Type: application/octet-stream`
  - Required Request Body: `<opaque raw authentication bytes>`
  - If Response Status 200:
    - Response Header: `Content-Type: application/json`
    - Response Body: `{ authToken: "<base64url-string>" }`
  - Status 401 indicates authentication bytes not accepted

## Addition of HTTP "Authorization" Header

If the SBD server requires authentication, clients should invoke the above authenticate api with authentication byte data obtained by means defined by the operators of the SBD server. Then, input the resultant authToken as an HTTP header when connecting to the SBD websocket api.

HTTP "Authorization" Header:

```
Authorization: Bearer <authToken base64url string>
```

## Server Configuration and Authentication Hook

The SBD server configuration will allow specifying a DNS or IP endpoint (the "Hook Server") at which a copy of the above specified REST endpoint is running.

If specified, the SBD server will relay the auth request to the hook server, record the returned authToken so it is treated as valid authorization token for future requests, and then return it.

If NOT specified, the SBD server will generate a random authToken, considering all client connections authenticated.

The SBD server will expire previously authorized tokens using the same logic and configured time periods for considering clients idle.

The hook server is free to return the same token to multiple clients. In that case, the token will remain valid if *any* of the clients are not idle.

The hook server is free to re-use expired tokens. They will be made valid again as a result of them being returned from the hook server /authenticate call.
