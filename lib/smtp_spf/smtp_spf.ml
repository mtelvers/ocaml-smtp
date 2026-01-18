(** SPF Verification - RFC 7208

    Sender Policy Framework validation to verify that a sending
    mail server is authorized by the domain owner. *)

open Smtp_dns

(** SPF check result per RFC 7208 Section 2.6 *)
type spf_result =
  | Spf_pass          (** Authorized sender *)
  | Spf_fail          (** Unauthorized - reject *)
  | Spf_softfail      (** Unauthorized - accept but mark *)
  | Spf_neutral       (** No assertion *)
  | Spf_none          (** No SPF record *)
  | Spf_temperror     (** Temporary error (DNS failure) *)
  | Spf_permerror     (** Permanent error (syntax error) *)

(** SPF check result with details *)
type spf_check_result = {
  result : spf_result;
  domain : string;
  explanation : string option;
}

(** SPF mechanism qualifier *)
type qualifier = Pass_q | Fail_q | Softfail_q | Neutral_q

(** SPF mechanism *)
type mechanism =
  | All
  | Include of string
  | A of string option * int option  (* domain, prefix_len *)
  | Mx of string option * int option
  | Ip4 of Smtp_dns.ip_addr * int    (* network, prefix_len *)
  | Ip6 of string * int
  | Exists of string
  | Ptr of string option  (* deprecated but still seen *)

(** Parse a qualifier prefix *)
let parse_qualifier s =
  if String.length s = 0 then (Neutral_q, s)
  else match s.[0] with
    | '+' -> (Pass_q, String.sub s 1 (String.length s - 1))
    | '-' -> (Fail_q, String.sub s 1 (String.length s - 1))
    | '~' -> (Softfail_q, String.sub s 1 (String.length s - 1))
    | '?' -> (Neutral_q, String.sub s 1 (String.length s - 1))
    | _ -> (Pass_q, s)  (* Default is pass *)

(** Parse CIDR prefix from mechanism *)
let parse_prefix s =
  match String.index_opt s '/' with
  | None -> (s, None)
  | Some i ->
    let base = String.sub s 0 i in
    let prefix = String.sub s (i + 1) (String.length s - i - 1) in
    (base, Some (int_of_string prefix))

(** Parse domain from mechanism (after colon) *)
let parse_domain_arg s =
  match String.index_opt s ':' with
  | None -> (s, None)
  | Some i ->
    let mech = String.sub s 0 i in
    let arg = String.sub s (i + 1) (String.length s - i - 1) in
    (mech, Some arg)

(** Parse an SPF mechanism *)
let parse_mechanism s domain =
  let (mech, arg) = parse_domain_arg s in
  let mech_lower = String.lowercase_ascii mech in
  match mech_lower with
  | "all" -> Some All
  | "include" ->
    (match arg with
     | Some d -> Some (Include d)
     | None -> None)  (* include requires domain *)
  | "a" ->
    let target = match arg with Some d -> d | None -> domain in
    let (target, prefix) = parse_prefix target in
    Some (A (Some target, prefix))
  | "mx" ->
    let target = match arg with Some d -> d | None -> domain in
    let (target, prefix) = parse_prefix target in
    Some (Mx (Some target, prefix))
  | "ip4" ->
    (match arg with
     | Some ip_str ->
       let (ip_str, prefix) = parse_prefix ip_str in
       let prefix = match prefix with Some p -> p | None -> 32 in
       (match parse_ip ip_str with
        | Some ip -> Some (Ip4 (ip, prefix))
        | None -> None)
     | None -> None)
  | "ip6" ->
    (match arg with
     | Some ip_str ->
       let (ip_str, prefix) = parse_prefix ip_str in
       let prefix = match prefix with Some p -> p | None -> 128 in
       Some (Ip6 (ip_str, prefix))
     | None -> None)
  | "exists" ->
    (match arg with
     | Some d -> Some (Exists d)
     | None -> None)
  | "ptr" ->
    Some (Ptr arg)
  | _ ->
    (* Unknown mechanism - could be a modifier like exp= or redirect= *)
    None

(** Parse SPF record into mechanisms *)
let parse_spf_record record domain =
  let parts = String.split_on_char ' ' record in
  (* First part should be v=spf1 *)
  match parts with
  | [] -> Error "Empty SPF record"
  | first :: rest ->
    if String.lowercase_ascii first <> "v=spf1" then
      Error "Not an SPF record (missing v=spf1)"
    else
      let mechanisms = List.filter_map (fun part ->
        let part = String.trim part in
        if String.length part = 0 then None
        else
          let (qual, mech_str) = parse_qualifier part in
          match parse_mechanism mech_str domain with
          | Some mech -> Some (qual, mech)
          | None ->
            (* Check for redirect modifier *)
            if String.length mech_str > 9 &&
               String.lowercase_ascii (String.sub mech_str 0 9) = "redirect=" then
              let target = String.sub mech_str 9 (String.length mech_str - 9) in
              Some (qual, Include target)  (* Treat redirect like include *)
            else
              None  (* Skip unknown mechanisms/modifiers *)
      ) rest in
      Ok mechanisms

(** Evaluate a single mechanism against client IP *)
let eval_mechanism dns client_ip domain = function
  | All -> Some true
  | Include _target_domain ->
    (* Recursively check included domain - limited depth *)
    None  (* Will be handled specially *)
  | A (target, prefix) ->
    let target_domain = match target with Some d -> d | None -> domain in
    let prefix = match prefix with Some p -> p | None -> 32 in
    (match lookup_a dns target_domain with
     | Ok addrs ->
       if List.exists (fun addr -> ip_in_network client_ip addr prefix) addrs then
         Some true
       else
         Some false
     | Error _ -> Some false)
  | Mx (target, prefix) ->
    let target_domain = match target with Some d -> d | None -> domain in
    let prefix = match prefix with Some p -> p | None -> 32 in
    (match lookup_mx dns target_domain with
     | Ok mx_records ->
       let matches = List.exists (fun (_, mx_host) ->
         match lookup_a dns mx_host with
         | Ok addrs -> List.exists (fun addr -> ip_in_network client_ip addr prefix) addrs
         | Error _ -> false
       ) mx_records in
       Some matches
     | Error _ -> Some false)
  | Ip4 (network, prefix) ->
    Some (ip_in_network client_ip network prefix)
  | Ip6 (_ip_str, _prefix) ->
    (* IPv6 matching - simplified *)
    Some false
  | Exists target_domain ->
    (match lookup_a dns target_domain with
     | Ok (_::_) -> Some true
     | _ -> Some false)
  | Ptr _ ->
    (* PTR mechanism is deprecated and complex - skip *)
    Some false

(** Convert qualifier to result *)
let qualifier_to_result = function
  | Pass_q -> Spf_pass
  | Fail_q -> Spf_fail
  | Softfail_q -> Spf_softfail
  | Neutral_q -> Spf_neutral

(** Maximum SPF lookup depth to prevent infinite loops *)
let max_depth = 10

(** Check SPF for a domain at a given depth *)
let rec check_spf_depth dns client_ip domain depth =
  if depth > max_depth then
    { result = Spf_permerror; domain; explanation = Some "Too many DNS lookups" }
  else
    (* Look up SPF record *)
    match lookup_txt dns domain with
    | Error Not_found ->
      { result = Spf_none; domain; explanation = Some "No SPF record" }
    | Error _ ->
      { result = Spf_temperror; domain; explanation = Some "DNS lookup failed" }
    | Ok txt_records ->
      (* Find SPF record (starts with v=spf1) *)
      let spf_records = List.filter (fun r ->
        let r_lower = String.lowercase_ascii r in
        String.length r_lower >= 6 && String.sub r_lower 0 6 = "v=spf1"
      ) txt_records in
      match spf_records with
      | [] ->
        { result = Spf_none; domain; explanation = Some "No SPF record" }
      | [record] ->
        (match parse_spf_record record domain with
         | Error msg ->
           { result = Spf_permerror; domain; explanation = Some msg }
         | Ok mechanisms ->
           eval_mechanisms dns client_ip domain mechanisms depth)
      | _ ->
        (* Multiple SPF records is an error *)
        { result = Spf_permerror; domain; explanation = Some "Multiple SPF records" }

(** Evaluate a list of mechanisms *)
and eval_mechanisms dns client_ip domain mechanisms depth =
  let rec loop = function
    | [] ->
      (* No mechanism matched - default is neutral *)
      { result = Spf_neutral; domain; explanation = Some "No matching mechanism" }
    | (qual, mech) :: rest ->
      match mech with
      | Include target_domain ->
        (* Recursive include check *)
        let sub_result = check_spf_depth dns client_ip target_domain (depth + 1) in
        (match sub_result.result with
         | Spf_pass -> { result = qualifier_to_result qual; domain; explanation = None }
         | Spf_fail | Spf_softfail | Spf_neutral -> loop rest  (* Continue to next mechanism *)
         | Spf_none | Spf_temperror | Spf_permerror -> loop rest)
      | _ ->
        (match eval_mechanism dns client_ip domain mech with
         | Some true ->
           { result = qualifier_to_result qual; domain; explanation = None }
         | Some false ->
           loop rest
         | None ->
           loop rest)
  in
  loop mechanisms

(** Check SPF for a sender's domain.

    @param dns DNS resolver
    @param client_ip IP address of the connecting client
    @param sender_domain Domain from MAIL FROM (or HELO if null sender)
    @return SPF check result *)
let check ~dns ~client_ip ~sender_domain =
  check_spf_depth dns client_ip sender_domain 0

(** Convert SPF result to string *)
let result_to_string = function
  | Spf_pass -> "pass"
  | Spf_fail -> "fail"
  | Spf_softfail -> "softfail"
  | Spf_neutral -> "neutral"
  | Spf_none -> "none"
  | Spf_temperror -> "temperror"
  | Spf_permerror -> "permerror"

(** Format SPF result for Received-SPF header *)
let format_received_spf result client_ip sender_domain =
  Printf.sprintf "%s (%s: %s) client-ip=%s;"
    (result_to_string result.result)
    sender_domain
    (match result.explanation with Some e -> e | None -> "")
    (ip_to_string client_ip)
