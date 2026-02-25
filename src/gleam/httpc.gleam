import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/charlist.{type Charlist}
import gleam/http.{type Method}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/list
import gleam/option
import gleam/result
import gleam/uri

pub type HttpError {
  /// The response body contained non-UTF-8 data, but UTF-8 data was expected.
  InvalidUtf8Response
  /// It was not possible to connect to the host.
  FailedToConnect(ip4: ConnectError, ip6: ConnectError)
  /// The response was not received within the configured timeout period.
  ResponseTimeout
}

pub type ConnectError {
  Posix(code: String)
  TlsAlert(code: String, detail: String)
}

pub type TlsVerification {
  /// Do not verify the server's TLS certificate.
  NoVerification
  /// Verify the server's TLS certificate using the system's default CA certificates.
  VerifyWithSystemCerts
  /// Verify the server's TLS certificate using a custom CA certificate file.
  /// The path should point to a PEM-encoded CA certificate file.
  VerifyWithCustomCa(path: String)
}

@external(erlang, "gleam_httpc_ffi", "default_user_agent")
fn default_user_agent() -> #(Charlist, Charlist)

@external(erlang, "gleam_httpc_ffi", "normalise_error")
fn normalise_error(error: Dynamic) -> HttpError

@external(erlang, "gleam_httpc_ffi", "ssl_verify_host_options")
fn ssl_verify_host_options(wildcard: Bool) -> List(ErlSslOption)

type ErlHttpOption {
  Ssl(List(ErlSslOption))
  Autoredirect(Bool)
  Timeout(Int)
}

type BodyFormat {
  Binary
}

type ErlOption {
  BodyFormat(BodyFormat)
  SocketOpts(List(SocketOpt))
}

type SocketOpt {
  Ipfamily(Inet6fb4)
}

type Inet6fb4 {
  Inet6fb4
}

type ErlSslOption {
  Verify(ErlVerifyOption)
  Certfile(Charlist)
  Keyfile(Charlist)
  Password(Charlist)
  Cacerts(List(BitArray))
  Cacertfile(Charlist)
  CustomizeHostnameCheck(List(Dynamic))
}

type ErlVerifyOption {
  VerifyNone
  VerifyPeer
}

@external(erlang, "httpc", "request")
fn erl_request(
  a: Method,
  b: #(Charlist, List(#(Charlist, Charlist)), Charlist, BitArray),
  c: List(ErlHttpOption),
  d: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

@external(erlang, "httpc", "request")
fn erl_request_no_body(
  a: Method,
  b: #(Charlist, List(#(Charlist, Charlist))),
  c: List(ErlHttpOption),
  d: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

fn string_header(header: #(Charlist, Charlist)) -> #(String, String) {
  let #(k, v) = header
  #(charlist.to_string(k), charlist.to_string(v))
}

// TODO: refine error type
/// Send a HTTP request of binary data using the default configuration.
///
/// If you wish to use some other configuration use `dispatch_bits` instead.
///
pub fn send_bits(
  req: Request(BitArray),
) -> Result(Response(BitArray), HttpError) {
  configure()
  |> dispatch_bits(req)
}

// TODO: refine error type
/// Send a HTTP request of binary data.
///
pub fn dispatch_bits(
  config: Configuration,
  req: Request(BitArray),
) -> Result(Response(BitArray), HttpError) {
  let erl_url =
    req
    |> request.to_uri
    |> uri.to_string
    |> charlist.from_string
  let erl_headers = prepare_headers(req.headers)
  let erl_http_options = [
    Autoredirect(config.follow_redirects),
    Timeout(config.timeout),
  ]
  let erl_http_options = case ssl_options(config) {
    option.Some(ssl) -> [Ssl(ssl), ..erl_http_options]
    option.None -> erl_http_options
  }
  let erl_options = [BodyFormat(Binary), SocketOpts([Ipfamily(Inet6fb4)])]

  use response <- result.try(
    case req.method {
      http.Options | http.Head | http.Get -> {
        let erl_req = #(erl_url, erl_headers)
        erl_request_no_body(req.method, erl_req, erl_http_options, erl_options)
      }
      _ -> {
        let erl_content_type =
          req
          |> request.get_header("content-type")
          |> result.unwrap("application/octet-stream")
          |> charlist.from_string
        let erl_req = #(erl_url, erl_headers, erl_content_type, req.body)
        erl_request(req.method, erl_req, erl_http_options, erl_options)
      }
    }
    |> result.map_error(normalise_error),
  )

  let #(#(_version, status, _status), headers, resp_body) = response
  Ok(Response(status, list.map(headers, string_header), resp_body))
}

fn verification_options(tls: TlsVerification) -> List(ErlSslOption) {
  case tls {
    VerifyWithSystemCerts -> ssl_verify_host_options(True)
    VerifyWithCustomCa(path) ->
      ssl_verify_host_options(True)
      |> list.map(fn(opt) {
        case opt {
          Cacerts(_) -> Cacertfile(charlist.from_string(path))
          _ -> opt
        }
      })
    NoVerification -> [Verify(VerifyNone)]
  }
}

fn certificate_options(
  cert: option.Option(ClientCertificate),
) -> List(ErlSslOption) {
  case cert {
    option.Some(ClientCertificate(certfile:, keyfile:, password:)) -> {
      let base = [
        Certfile(charlist.from_string(certfile)),
        Keyfile(charlist.from_string(keyfile)),
      ]
      case password {
        option.Some(pw) -> [Password(charlist.from_string(pw)), ..base]
        option.None -> base
      }
    }
    option.None -> []
  }
}

fn ssl_options(config: Configuration) -> option.Option(List(ErlSslOption)) {
  let cert_opts = certificate_options(config.client_certificate)
  let verify_opts = verification_options(config.tls_verification)

  case config.tls_verification, cert_opts {
    VerifyWithSystemCerts, [] -> option.None
    _, _ -> option.Some(list.append(verify_opts, cert_opts))
  }
}

/// Configuration that can be used to send HTTP requests.
///
/// To be used with `dispatch` and `dispatch_bits`.
///
pub opaque type Configuration {
  Builder(
    /// How TLS verification should be performed.
    ///
    tls_verification: TlsVerification,
    /// Whether to follow redirects.
    ///
    follow_redirects: Bool,
    /// Timeout for the request in milliseconds.
    ///
    timeout: Int,
    /// Client certificate and private key for TLS authentication.
    ///
    client_certificate: option.Option(ClientCertificate),
  )
}

type ClientCertificate {
  ClientCertificate(
    certfile: String,
    keyfile: String,
    password: option.Option(String),
  )
}

/// Create a new configuration with the default settings.
///
/// # Defaults
///
/// - TLS is verified.
/// - Redirects are not followed.
/// - The timeout for the response to be received is 30 seconds from when the
///   request is sent.
/// - No client certificates are sent
///
pub fn configure() -> Configuration {
  Builder(
    tls_verification: VerifyWithSystemCerts,
    follow_redirects: False,
    timeout: 30_000,
    client_certificate: option.None,
  )
}

/// Set whether to verify the TLS certificate of the server.
///
/// This defaults to `VerifyWithSystemCerts`, meaning that the TLS certificate
/// will be verified using the system's default CA certificates unless you call this function with a different option.
///
/// Setting this to `NoVerification` can make your application vulnerable to
/// man-in-the-middle attacks and other security risks. Do not do this unless
/// you are sure and you understand the risks.
///
pub fn verify_tls(
  config: Configuration,
  tls_verification: TlsVerification,
) -> Configuration {
  Builder(..config, tls_verification:)
}

/// Set whether redirects should be followed automatically.
pub fn follow_redirects(config: Configuration, which: Bool) -> Configuration {
  Builder(..config, follow_redirects: which)
}

/// Set the timeout in milliseconds, the default being 30 seconds.
///
/// If the response is not recieved within this amount of time then the
/// client disconnects and an error is returned.
///
pub fn timeout(config: Configuration, timeout: Int) -> Configuration {
  Builder(..config, timeout:)
}

/// Set a client certificate and private key for mutual TLS.
///
pub fn client_certificate(
  config: Configuration,
  certfile certfile: String,
  keyfile keyfile: String,
) -> Configuration {
  Builder(
    ..config,
    client_certificate: option.Some(ClientCertificate(
      certfile:,
      keyfile:,
      password: option.None,
    )),
  )
}

/// Set a client certificate and private key for mutual TLS,
/// with a password for an encrypted private key.
///
pub fn client_certificate_with_password(
  config: Configuration,
  certfile certfile: String,
  keyfile keyfile: String,
  password password: String,
) -> Configuration {
  Builder(
    ..config,
    client_certificate: option.Some(ClientCertificate(
      certfile:,
      keyfile:,
      password: option.Some(password),
    )),
  )
}

/// Send a HTTP request of unicode data.
///
pub fn dispatch(
  config: Configuration,
  request: Request(String),
) -> Result(Response(String), HttpError) {
  let request = request.map(request, bit_array.from_string)
  use resp <- result.try(dispatch_bits(config, request))

  case bit_array.to_string(resp.body) {
    Ok(body) -> Ok(response.set_body(resp, body))
    Error(_) -> Error(InvalidUtf8Response)
  }
}

// TODO: refine error type
/// Send a HTTP request of unicode data using the default configuration.
///
/// If you wish to use some other configuration use `dispatch` instead.
///
pub fn send(req: Request(String)) -> Result(Response(String), HttpError) {
  configure()
  |> dispatch(req)
}

fn prepare_headers(
  headers: List(#(String, String)),
) -> List(#(Charlist, Charlist)) {
  prepare_headers_loop(headers, [], False)
}

fn prepare_headers_loop(
  in: List(#(String, String)),
  out: List(#(Charlist, Charlist)),
  user_agent_set: Bool,
) -> List(#(Charlist, Charlist)) {
  case in {
    [] if user_agent_set -> out
    [] -> [default_user_agent(), ..out]
    [#(k, v), ..in] -> {
      let user_agent_set = user_agent_set || k == "user-agent"
      let out = [#(charlist.from_string(k), charlist.from_string(v)), ..out]
      prepare_headers_loop(in, out, user_agent_set)
    }
  }
}
