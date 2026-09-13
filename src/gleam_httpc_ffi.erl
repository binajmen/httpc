-module(gleam_httpc_ffi).
-export([default_user_agent/0, normalise_error/1, https_hostname_check/0]).

normalise_error(Error = {failed_connect, Opts}) ->
    Ipv6 = case lists:keyfind(inet6, 1, Opts) of
        {inet6, _, V1} -> V1;
        _ -> erlang:error({unexpected_httpc_error, Error})
    end,
    Ipv4 = case lists:keyfind(inet, 1, Opts) of
        {inet, _, V2} -> V2;
        _ -> erlang:error({unexpected_httpc_error, Error})
    end,
    {failed_to_connect, normalise_ip_error(Ipv4), normalise_ip_error(Ipv6)};
%% With TLS 1.3 a server rejects a missing or invalid client certificate after
%% the handshake has completed, so httpc reports it as a socket error rather
%% than a connect failure. Normalise it to the same error TLS 1.2 produces.
normalise_error({ssl_error, _Socket, Reason}) ->
    {failed_to_connect, normalise_ip_error(Reason), normalise_ip_error(Reason)};
normalise_error(timeout) ->
    response_timeout;
normalise_error(socket_closed_remotely) ->
    connection_closed;
normalise_error(Error) ->
    erlang:error({unexpected_httpc_error, Error}).

normalise_ip_error(Code) when is_atom(Code) ->
    {posix, erlang:atom_to_binary(Code)};
normalise_ip_error({tls_alert, {A, B}}) ->
    {tls_alert, erlang:atom_to_binary(A), unicode:characters_to_binary(B)};
normalise_ip_error({options, _} = Reason) ->
    {invalid_tls_options, format_reason(Reason)};
normalise_ip_error({options, incompatible, _} = Reason) ->
    {invalid_tls_options, format_reason(Reason)};
%% ssl re-throws some file errors without the {options, _} wrapper, for
%% example an encrypted key file used without a password.
normalise_ip_error({Opt, _} = Reason) when Opt =:= keyfile; Opt =:= certfile; Opt =:= cacertfile ->
    {invalid_tls_options, format_reason(Reason)};
normalise_ip_error(Error) ->
    erlang:error({unexpected_httpc_ip_error, Error}).

format_reason(Reason) ->
    unicode:characters_to_binary(io_lib:format("~p", [Reason])).

default_user_agent() ->
    Version =
        case application:get_key(gleam_httpc, vsn) of
            {ok, V} when is_list(V) -> V;
            undefined -> "0.0.0"
        end,
    {"user-agent", "gleam_httpc/" ++ Version}.

https_hostname_check() ->
    {customize_hostname_check,
     [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}.
