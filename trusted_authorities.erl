-module(trusted_authorities).
-compile(export_all).

% straight from TrustedAuthorities.java of JTor
-define(DIRSERVERS, [
	"authority moria1 orport=9101 no-v2 v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
	"authority tor26 v1 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
	"authority dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
	"authority Tonga orport=443 bridge no-v2 82.94.251.203:80 4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
	"authority ides orport=9090 no-v2 v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 216.224.124.114:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
	"authority gabelmoo orport=8080 no-v2 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 80.190.246.100:8180 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
	"authority dannenberg orport=443 no-v2 v3ident=585769C78764D58426B8B52B6651A5A71137189A 213.73.91.31:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
	"authority urras orport=80 no-v2 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417"
]).

-record(dir_auth_status, {
	nickname,
	identity = <<>>,
	address,
	router_port,
	directory_port,
	flags = sets:from_list([authority, v2dir]),
	v3ident
}).

init() ->
	lists:map(fun str_to_authority/1, ?DIRSERVERS).

str_to_authority(Str) ->
	["authority", Nickname | Tokens] = string:tokens(Str, " "),
	lists:foldl(fun parse_authority/2, #dir_auth_status{nickname = Nickname}, Tokens).

parse_authority(Word, Auth) ->
	case Word of
		"v1" -> add_hs_authority(Auth);
		"hs" -> add_hs_authority(Auth);
		"no-hs" -> del_hs_authority(Auth);
		"bridge" -> Auth;
		"no-v2" -> del_v2_authority(Auth);
		[$o, $r, $p, $o, $r, $t, $= | Port] ->
			Auth#dir_auth_status{router_port = list_to_integer(Port)};
		[$v, $3, $i, $d, $e, $n, $t, $= | V3ident ] ->
			Auth#dir_auth_status{v3ident = hex:hexstr_to_bin(V3ident)};
		FP = [_, _, _, _] ->
			OldBin = Auth#dir_auth_status.identity, 
			Append = hex:hexstr_to_bin(FP),
			Auth#dir_auth_status{identity = <<OldBin/binary, Append/binary>>};
		Addr = [F | _] when F >= $0 andalso F =< $9 ->
			[IP, Port] = string:tokens(Addr, ":"),
			Auth#dir_auth_status{address = IP, directory_port = list_to_integer(Port)}
	end.

add_hs_authority(Auth) -> manage_flags(hs_dir, fun sets:add_element/2).
del_hs_authority(Auth) -> manage_flags(hs_dir, fun sets:del_element/2).
del_v2_authority(Auth) -> manage_flags(v2_dir, fun sets:del_element/2).

manage_flags(Flag, Fun) ->
	Auth#dir_auth_status{flags = Fun(Flag, Auth#dir_auth_status.flags)}.
