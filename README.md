# httpc

Bindings to Erlang's built in HTTP client, `httpc`.

[![Package Version](https://img.shields.io/hexpm/v/gleam_httpc)](https://hex.pm/packages/gleam_httpc)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gleam_httpc/)

```sh
gleam add gleam_httpc@5
```
```gleam
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/result

pub fn send_request() {
  // Prepare a HTTP request record
  let assert Ok(base_req) =
    request.to("https://test-api.service.hmrc.gov.uk/hello/world")

  let req =
    request.prepend_header(base_req, "accept", "application/vnd.hmrc.1.0+json")

  // Send the HTTP request to the server
  use resp <- result.try(httpc.send(req))

  // We get a response record back
  assert resp.status == 200

  let content_type = response.get_header(resp, "content-type")
  assert content_type == Ok("application/json")

  assert resp.body == "{\"message\":\"Hello World\"}"

  Ok(resp)
}
```

## TLS options

Server certificates are verified against the system's CA certificates by
default. A `Configuration` can verify against a custom CA instead, or present a
client certificate for mutual TLS:

```gleam
import gleam/httpc

pub fn send_request(req) {
  httpc.configure()
  |> httpc.verify_tls(httpc.VerifyWithCustomCa("/path/to/ca.pem"))
  |> httpc.client_certificate(
    certfile: "/path/to/client.pem",
    keyfile: "/path/to/client.key",
  )
  |> httpc.dispatch(req)
}
```

This library requires Erlang/OTP 25.1 or later.
