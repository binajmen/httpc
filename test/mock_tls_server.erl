-module(mock_tls_server).
-export([start/0, https_port/0, mtls_port/0, ca_file/0, client_cert_file/0,
         client_key_file/0, client_key_encrypted_file/0]).

-include_lib("public_key/include/public_key.hrl").

-define(PASSWORD, "secret").

%% Starts two HTTPS listeners backed by a throwaway PKI generated at runtime:
%% one that only presents a server certificate, and one that additionally
%% requires a client certificate. Both reply 200 to any request.
start() ->
    Files = generate_certs(),
    ServerOpts = [{certfile, maps:get(server_cert_file, Files)},
                  {keyfile, maps:get(server_key_file, Files)}],
    MtlsOpts = ServerOpts ++ [{verify, verify_peer},
                              {cacerts, maps:get(client_cacerts, Files)},
                              {fail_if_no_peer_cert, true}],
    persistent_term:put({?MODULE, files}, Files),
    persistent_term:put({?MODULE, https_port}, listen(ServerOpts)),
    persistent_term:put({?MODULE, mtls_port}, listen(MtlsOpts)),
    nil.

https_port() -> persistent_term:get({?MODULE, https_port}).
mtls_port() -> persistent_term:get({?MODULE, mtls_port}).
ca_file() -> file(ca_file).
client_cert_file() -> file(client_cert_file).
client_key_file() -> file(client_key_file).
client_key_encrypted_file() -> file(client_key_encrypted_file).

file(Key) -> maps:get(Key, persistent_term:get({?MODULE, files})).

generate_certs() ->
    San = #'Extension'{extnID = ?'id-ce-subjectAltName', critical = false,
                       extnValue = [{dNSName, "localhost"}]},
    Key = {key, {namedCurve, secp256r1}},
    %% pkix_test_data signs with SHA-1 by default, which TLS 1.3 rejects.
    Digest = {digest, sha256},
    #{server_config := Server, client_config := Client} =
        public_key:pkix_test_data(#{
            server_chain => #{root => [Key, Digest], intermediates => [],
                              peer => [Key, Digest, {extensions, [San]}]},
            client_chain => #{root => [Key, Digest], intermediates => [],
                              peer => [Key, Digest]}}),
    %% Random rather than unique_integer, which repeats across VMs. The files
    %% are left behind: they must outlive the suite and gleeunit has no teardown.
    Suffix = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))),
    Dir = filename:join(os:getenv("TMPDIR", "/tmp"), "gleam_httpc_test_" ++ Suffix),
    ok = file:make_dir(Dir),
    %% Each side's cacerts are the CAs it must trust to verify the other side.
    {cacerts, ServerCas} = lists:keyfind(cacerts, 1, Client),
    {cacerts, ClientCas} = lists:keyfind(cacerts, 1, Server),
    {cert, ServerCert} = lists:keyfind(cert, 1, Server),
    {key, ServerKey} = lists:keyfind(key, 1, Server),
    {cert, ClientCert} = lists:keyfind(cert, 1, Client),
    {key, {KeyType, KeyDer} = ClientKey} = lists:keyfind(key, 1, Client),
    Encrypted = public_key:pem_entry_encode(
                  KeyType, public_key:der_decode(KeyType, KeyDer),
                  {{"AES-128-CBC", crypto:strong_rand_bytes(16)}, ?PASSWORD}),
    #{ca_file => write(Dir, "ca.pem", certs_pem(ServerCas)),
      server_cert_file => write(Dir, "server.pem", certs_pem([ServerCert])),
      server_key_file => write(Dir, "server.key", key_pem(ServerKey)),
      client_cert_file => write(Dir, "client.pem", certs_pem([ClientCert])),
      client_key_file => write(Dir, "client.key", key_pem(ClientKey)),
      client_key_encrypted_file =>
          write(Dir, "client_enc.key", public_key:pem_encode([Encrypted])),
      client_cacerts => ClientCas}.

certs_pem(Ders) ->
    public_key:pem_encode([{'Certificate', Der, not_encrypted} || Der <- Ders]).

key_pem({Type, Der}) ->
    public_key:pem_encode([{Type, Der, not_encrypted}]).

write(Dir, Name, Contents) ->
    Path = filename:join(Dir, Name),
    ok = file:write_file(Path, Contents),
    unicode:characters_to_binary(Path).

listen(SslOpts) ->
    {ok, Listen} = ssl:listen(0, [binary, {active, false}, {reuseaddr, true} | SslOpts]),
    {ok, {_, Port}} = ssl:sockname(Listen),
    spawn_link(fun() -> accept_loop(Listen) end),
    Port.

accept_loop(Listen) ->
    {ok, Transport} = ssl:transport_accept(Listen),
    spawn(fun() -> serve(Transport) end),
    accept_loop(Listen).

serve(Transport) ->
    case ssl:handshake(Transport, 5000) of
        {ok, Socket} ->
            _ = ssl:recv(Socket, 0, 5000),
            ok = ssl:send(Socket, <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
                                    "connection: close\r\n\r\nok">>),
            ssl:close(Socket);
        {error, _} ->
            ok
    end.
