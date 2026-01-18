(** SMTP DNS Resolver

    DNS lookups for SPF, DKIM, and DMARC verification.
    Uses system DNS resolution via Unix commands. *)

(** DNS lookup errors *)
type error =
  | Not_found
  | Timeout
  | Server_failure
  | Format_error of string

(** DNS resolver type (stateless, uses system resolver) *)
type t = unit

(** Create a new DNS resolver *)
let create () = ()

(** Run a command and capture output *)
let run_command cmd =
  let ic = Unix.open_process_in cmd in
  let buf = Buffer.create 256 in
  (try
     while true do
       Buffer.add_channel buf ic 1
     done
   with End_of_file -> ());
  let status = Unix.close_process_in ic in
  match status with
  | Unix.WEXITED 0 -> Ok (Buffer.contents buf)
  | _ -> Error (Format_error "Command failed")

(** Look up TXT records for a domain.
    Used for SPF, DKIM, and DMARC record retrieval. *)
let lookup_txt () domain =
  (* Use dig for TXT lookups - more reliable than host for TXT records *)
  let cmd = Printf.sprintf "dig +short TXT %s 2>/dev/null" (Filename.quote domain) in
  match run_command cmd with
  | Error e -> Error e
  | Ok output ->
    let lines = String.split_on_char '\n' output in
    let records = List.filter_map (fun line ->
      let line = String.trim line in
      if String.length line > 2 && line.[0] = '"' then
        (* Remove surrounding quotes and unescape *)
        let unquoted = String.sub line 1 (String.length line - 2) in
        (* Handle split TXT records (multiple quoted strings) *)
        let unescaped = Str.global_replace (Str.regexp {|"[ \t]*"|}) "" unquoted in
        Some unescaped
      else if String.length line > 0 then
        Some line
      else
        None
    ) lines in
    if records = [] then Error Not_found
    else Ok records

(** Parse IPv4 address from string *)
let parse_ipv4 s =
  try
    match String.split_on_char '.' s with
    | [a; b; c; d] ->
      let a = int_of_string a and b = int_of_string b
      and c = int_of_string c and d = int_of_string d in
      if a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
         c >= 0 && c <= 255 && d >= 0 && d <= 255 then
        Some (a, b, c, d)
      else None
    | _ -> None
  with _ -> None

(** Parse IPv6 address from string - simplified *)
let parse_ipv6 s =
  (* Very basic IPv6 parsing - just validate format *)
  let parts = String.split_on_char ':' s in
  if List.length parts >= 2 && List.length parts <= 8 then
    Some s
  else
    None

(** IP address type *)
type ip_addr =
  | IPv4 of int * int * int * int
  | IPv6 of string

(** Convert IP address to string *)
let ip_to_string = function
  | IPv4 (a, b, c, d) -> Printf.sprintf "%d.%d.%d.%d" a b c d
  | IPv6 s -> s

(** Parse IP address from string *)
let parse_ip s =
  match parse_ipv4 s with
  | Some (a, b, c, d) -> Some (IPv4 (a, b, c, d))
  | None ->
    match parse_ipv6 s with
    | Some s -> Some (IPv6 s)
    | None -> None

(** Look up A records for a domain *)
let lookup_a () domain =
  let cmd = Printf.sprintf "dig +short A %s 2>/dev/null" (Filename.quote domain) in
  match run_command cmd with
  | Error e -> Error e
  | Ok output ->
    let lines = String.split_on_char '\n' output in
    let addrs = List.filter_map (fun line ->
      let line = String.trim line in
      match parse_ipv4 line with
      | Some (a, b, c, d) -> Some (IPv4 (a, b, c, d))
      | None -> None
    ) lines in
    if addrs = [] then Error Not_found
    else Ok addrs

(** Look up AAAA records for a domain *)
let lookup_aaaa () domain =
  let cmd = Printf.sprintf "dig +short AAAA %s 2>/dev/null" (Filename.quote domain) in
  match run_command cmd with
  | Error e -> Error e
  | Ok output ->
    let lines = String.split_on_char '\n' output in
    let addrs = List.filter_map (fun line ->
      let line = String.trim line in
      if String.length line > 0 && String.contains line ':' then
        Some (IPv6 line)
      else
        None
    ) lines in
    if addrs = [] then Error Not_found
    else Ok addrs

(** Look up MX records for a domain *)
let lookup_mx () domain =
  let cmd = Printf.sprintf "dig +short MX %s 2>/dev/null" (Filename.quote domain) in
  match run_command cmd with
  | Error e -> Error e
  | Ok output ->
    let lines = String.split_on_char '\n' output in
    let records = List.filter_map (fun line ->
      let line = String.trim line in
      match String.split_on_char ' ' line with
      | [pref; host] ->
        (try Some (int_of_string pref, host)
         with _ -> None)
      | _ -> None
    ) lines in
    let sorted = List.sort (fun (p1, _) (p2, _) -> compare p1 p2) records in
    if sorted = [] then Error Not_found
    else Ok sorted

(** Look up PTR record for an IP address *)
let lookup_ptr () ip =
  let ptr_domain = match ip with
    | IPv4 (a, b, c, d) ->
      Printf.sprintf "%d.%d.%d.%d.in-addr.arpa" d c b a
    | IPv6 _ ->
      (* IPv6 PTR is complex - skip for now *)
      ""
  in
  if ptr_domain = "" then Error Not_found
  else
    let cmd = Printf.sprintf "dig +short PTR %s 2>/dev/null" (Filename.quote ptr_domain) in
    match run_command cmd with
    | Error e -> Error e
    | Ok output ->
      let line = String.trim output in
      if String.length line > 0 then Ok line
      else Error Not_found

(** Check if an IPv4 address matches a CIDR network *)
let ipv4_in_network (a1, b1, c1, d1) (a2, b2, c2, d2) prefix_len =
  let ip1 = (a1 lsl 24) lor (b1 lsl 16) lor (c1 lsl 8) lor d1 in
  let ip2 = (a2 lsl 24) lor (b2 lsl 16) lor (c2 lsl 8) lor d2 in
  let mask = if prefix_len = 0 then 0 else (-1) lsl (32 - prefix_len) in
  (ip1 land mask) = (ip2 land mask)

(** Check if an IP address matches a CIDR network *)
let ip_in_network ip network prefix_len =
  match ip, network with
  | IPv4 (a1, b1, c1, d1), IPv4 (a2, b2, c2, d2) ->
    ipv4_in_network (a1, b1, c1, d1) (a2, b2, c2, d2) prefix_len
  | IPv6 _, IPv6 _ -> false  (* IPv6 CIDR matching not implemented *)
  | _ -> false

(** Check if IP matches a domain's A/AAAA records *)
let ip_matches_domain () ip domain =
  match ip with
  | IPv4 _ ->
    (match lookup_a () domain with
     | Ok addrs -> List.exists (fun a -> a = ip) addrs
     | Error _ -> false)
  | IPv6 _ ->
    (match lookup_aaaa () domain with
     | Ok addrs -> List.exists (fun a -> a = ip) addrs
     | Error _ -> false)
