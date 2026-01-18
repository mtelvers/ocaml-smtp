(** SMTP Authentication Module

    Implements SASL authentication ({{:https://datatracker.ietf.org/doc/html/rfc4954}RFC 4954})
    for SMTP. Supports PLAIN ({{:https://datatracker.ietf.org/doc/html/rfc4616}RFC 4616}) and
    LOGIN mechanisms. *)

(** Authentication backend interface *)
module type AUTH = sig
  type t

  (** Create an authentication backend.
      @param service_name PAM service name (e.g., "smtpd") *)
  val create : service_name:string -> t

  (** Authenticate a user with username and password.
      @return true if authentication succeeds *)
  val authenticate : t -> username:string -> password:string -> bool
end

(* External C functions for PAM *)
external pam_authenticate_ext : string -> string -> string -> bool = "caml_pam_authenticate"
external pam_available_ext : unit -> bool = "caml_pam_available"

(** PAM-based authentication backend.

    Uses the system PAM configuration for authentication.
    Requires a PAM service file (e.g., /etc/pam.d/smtpd). *)
module Pam_auth : sig
  include AUTH

  (** Check if PAM is available on this system *)
  val is_available : unit -> bool
end = struct
  type t = {
    service_name : string;
  }

  let create ~service_name = { service_name }

  let authenticate t ~username ~password =
    pam_authenticate_ext t.service_name username password

  let is_available () = pam_available_ext ()
end

(** Mock authentication backend for testing.

    Stores users in memory. Useful for development and testing
    without requiring system PAM configuration. *)
module Mock_auth : sig
  include AUTH

  (** Add a user with the given credentials *)
  val add_user : t -> username:string -> password:string -> unit

  (** Remove a user *)
  val remove_user : t -> username:string -> unit

  (** List all registered usernames *)
  val list_users : t -> string list
end = struct
  type t = {
    mutable users : (string * string) list;
    service_name : string;
  }

  let create ~service_name = { users = []; service_name }

  let add_user t ~username ~password =
    t.users <- (username, password) :: List.filter (fun (u, _) -> u <> username) t.users

  let remove_user t ~username =
    t.users <- List.filter (fun (u, _) -> u <> username) t.users

  let authenticate t ~username ~password =
    List.exists (fun (u, p) -> u = username && p = password) t.users

  let list_users t =
    List.map fst t.users
end
