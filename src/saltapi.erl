%%  This library allows easy(-ish) requests from the Salt API server.
%%
%%  Documentation for the API can be found at https://tinyurl.com/opsoatz
%%
%%  In the code below, Client indicates one of
%%      local  - like the salt CLI command
%%      runner - like the salt-run CLI command
%%      wheel  - used for salt-key commands among others
%%
%%  Target is a minion specification like "*" or "bloom-*".
%%
%%  Function is something akin to "test.ping" or "key.list_all".
%%
%%  Params is a map with two interesting (and optional) keys:
%%      kwarg => a map of keyword arguments to the function
%%      arg   => a list of positional parameters for the function
%%
%%  Type is an optional parameter.  Its default value is sync but
%%  async is also accepted.


-module(saltapi).
-export([
          credentials/0
        , password_reader/1
        , endpoint/0
        , token/0
        , ping/0
        , request/3
        , request/4
        , request/5
        ]).

-type salt_response() :: map().

%% @doc Send a test.ping to each of the registered minions
-spec ping() -> salt_response().
ping() ->
  request(local, "*", "test.ping").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% HTTP Requests                                                          %%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% @doc Send a synchronous request to the salt API server.
request(Client, Target, Function) ->
  request(sync, Client, Target, Function, #{}).

request(Client, Target, Function, Params) ->
  request(sync, Client, Target, Function, Params).

request(Type, Client, Target, Function, Params) ->
  {Arg, Kwarg} = parse_params(Params),
  Payload = make_payload(Client, Target, Function, Arg, Kwarg),
  call_api(Type, Payload).


%% INTERNAL
to_binary(X) when is_binary(X) -> X;
to_binary(X) when is_list(X)   -> list_to_binary(X);
to_binary(X) when is_atom(X)   -> atom_to_binary(X, utf8).

parse_params(Params) ->
  Arg = parse_params(arg, Params),
  Kwarg = parse_params(kwarg, Params),
  {Arg, Kwarg}.

parse_params(arg, Params) ->
  [ to_binary(X) || X <- maps:get(arg, Params, []) ];
parse_params(kwarg, Params) ->
  maps:fold(fun(K, V, Acc) -> maps:put(to_binary(K), to_binary(V), Acc) end,
            #{}, maps:get(kwarg, Params, #{})).


make_payload(Client, Target, Function, Arg, Kwarg) ->
  jsx:encode([{<<"client">>, to_binary(Client)},
              {<<"tgt">>,    to_binary(Target)},
              {<<"fun">>,    to_binary(Function)},
              {<<"arg">>,    Arg},
              {<<"kwarg">>,  Kwarg}]).

make_headers(Type, Payload) ->
  H1 = [{"Content-type", "application/json"},
        {"X-Auth-Token", token()},
        {"Accept", "application/json"},
        {"Content-Length", size(Payload)}],
  case Type of
    sync -> H1;
    async -> [{stream_to, self()} | H1]
  end.


call_api(sync, Payload) ->
  Timeout = 60 * 3 * 1000, % three minutes
  {_, _, _, Res} = ibrowse:send_req(endpoint(), make_headers(sync, Payload),
                                    post, Payload, conn_options(), Timeout),
  decode_results(Res);
call_api(async, Payload) ->
  {ibrowse_req_id, _ReqID} =
    ibrowse:send_req(endpoint(), make_headers(async, Payload),
                     post, Payload, conn_options()).

decode_results(Res) ->
  jsx:decode(list_to_binary(Res), [{labels, atom}, return_maps]).

conn_options() ->
  application:get_env(saltapi, ibrowse_opts, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Authentication                                                         %%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec credentials() -> {any(), any()}.
credentials() ->
  User = case application:get_env(saltapi, user) of
           {ok, Name} -> Name;
           _          -> error("saltapi user missing")
         end,
  Pass = case application:get_env(saltapi, pass) of
           {ok, {function, M, F, A}} -> apply(M, F, A);
           {ok, Token}               -> Token;
           _                         -> error("saltapi pass missing")
         end,
  {User, Pass}.

password_reader(PasswordFile) ->
  {ok, Password} = file:read_file(PasswordFile),
  string:trim(binary_to_list(Password)).

-spec endpoint() -> string() | binary().
endpoint() ->
  case application:get_env(saltapi, endpoint) of
    {ok, URL} -> URL;
    _         -> error("Endpoint must be configured.")
  end.

-spec token() -> string().
token() ->
  Payload = list_to_binary(creds_to_querystring()),
  {ok, "200", Headers, _} =
    ibrowse:send_req(login_url(),
                     [{"Content-Type", "application/x-www-form-urlencoded"},
                      {"Accept", "application/json"},
                      {"Content-Length", size(Payload)}],
                     post, Payload, conn_options()),
  proplists:get_value("X-Auth-Token", Headers).

%% INTERNAL
login_url() -> endpoint() ++ "/login".

creds_to_querystring() ->
  {User, Pass} = credentials(),
  io_lib:format("username=~s&password=~s&eauth=pam",
                [ibrowse_lib:url_encode(User),
                 ibrowse_lib:url_encode(Pass)]).
