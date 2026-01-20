(** SMTP Message Queue

    Stores messages accepted by the SMTP server for delivery or local storage. *)

open Smtp_types

(** Queue error types *)
type error =
  | Queue_full
  | Message_too_large
  | Storage_error of string

(** Queue statistics *)
type stats = {
  pending : int;
  total_size : int64;
}

(** Queue backend interface *)
module type QUEUE = sig
  type t

  (** Create a new queue *)
  val create : unit -> t

  (** Enqueue a message.
      @return Ok queue_id on success, Error on failure *)
  val enqueue : t -> queued_message -> (string, error) result

  (** Dequeue the next message for delivery.
      @return Some message if available, None if queue is empty *)
  val dequeue : t -> queued_message option

  (** Peek at up to n messages without removing them *)
  val peek : t -> int -> queued_message list

  (** Get a specific message by ID *)
  val get : t -> id:string -> queued_message option

  (** Mark a message as successfully delivered and remove from queue *)
  val mark_delivered : t -> id:string -> (unit, error) result

  (** Mark a message as failed with reason (may trigger retry or bounce) *)
  val mark_failed : t -> id:string -> reason:string -> (unit, error) result

  (** Get queue statistics *)
  val get_stats : t -> stats
end

(** Generate a unique queue ID *)
let generate_queue_id () =
  let timestamp = Unix.gettimeofday () in
  let random = Random.int 0xFFFFFF in
  Printf.sprintf "%d.%06X" (int_of_float (timestamp *. 1000.0)) random

(** In-memory queue backend.

    Suitable for development and testing. Messages are not persisted. *)
module Memory_queue : QUEUE = struct
  type t = {
    mutable messages : queued_message list;
    mutable max_size : int;
    mutable max_messages : int;
  }

  let create () = {
    messages = [];
    max_size = 50 * 1024 * 1024;  (* 50MB default *)
    max_messages = 10000;
  }

  let total_size t =
    List.fold_left (fun acc m -> Int64.add acc (Int64.of_int (String.length m.data))) 0L t.messages

  let enqueue t msg =
    if List.length t.messages >= t.max_messages then
      Error Queue_full
    else if Int64.compare (total_size t) (Int64.of_int t.max_size) > 0 then
      Error Queue_full
    else begin
      let msg = { msg with id = generate_queue_id () } in
      t.messages <- t.messages @ [msg];
      Ok msg.id
    end

  let dequeue t =
    match t.messages with
    | [] -> None
    | msg :: rest ->
      t.messages <- rest;
      Some msg

  let peek t n =
    let rec take n acc = function
      | [] -> List.rev acc
      | _ when n <= 0 -> List.rev acc
      | x :: xs -> take (n - 1) (x :: acc) xs
    in
    take n [] t.messages

  let get t ~id =
    List.find_opt (fun m -> m.id = id) t.messages

  let mark_delivered t ~id =
    let found = List.exists (fun m -> m.id = id) t.messages in
    if found then begin
      t.messages <- List.filter (fun m -> m.id <> id) t.messages;
      Ok ()
    end else
      Error (Storage_error "Message not found")

  let mark_failed t ~id ~reason:_ =
    (* In memory queue, just remove failed messages *)
    mark_delivered t ~id

  let get_stats t = {
    pending = List.length t.messages;
    total_size = total_size t;
  }
end

(** File-based queue backend.

    Stores messages as individual files in a spool directory.
    Suitable for production use with persistence. *)
module File_queue : sig
  include QUEUE

  (** Create a queue with a specific spool directory *)
  val create_with_path : base_path:string -> t
end = struct
  type t = {
    base_path : string;
    mutable index : (string * string) list;  (* id -> filename *)
  }

  let create () = {
    base_path = "/var/spool/smtpd";
    index = [];
  }

  let load_existing base_path =
    try
      let entries = Sys.readdir base_path in
      Array.fold_left (fun acc entry ->
        if Filename.check_suffix entry ".msg" then begin
          let id = Filename.chop_suffix entry ".msg" in
          let path = Filename.concat base_path entry in
          (id, path) :: acc
        end else acc
      ) [] entries
    with _ -> []

  let create_with_path ~base_path =
    let index = load_existing base_path in
    { base_path; index }

  let ensure_dir path =
    try
      Unix.mkdir path 0o750
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  let message_path t id =
    Filename.concat t.base_path (id ^ ".msg")

  let serialize_message msg =
    (* Simple format: headers then body *)
    let buf = Buffer.create (String.length msg.data + 512) in
    Buffer.add_string buf (Printf.sprintf "X-Queue-Id: %s\r\n" msg.id);
    Buffer.add_string buf (Printf.sprintf "X-Sender: %s\r\n"
      (reverse_path_to_string msg.sender));
    List.iter (fun rcpt ->
      Buffer.add_string buf (Printf.sprintf "X-Recipient: %s\r\n"
        (email_to_string rcpt))
    ) msg.recipients;
    Buffer.add_string buf (Printf.sprintf "X-Received-At: %.6f\r\n" msg.received_at);
    (match msg.auth_user with
     | Some user -> Buffer.add_string buf (Printf.sprintf "X-Auth-User: %s\r\n" user)
     | None -> ());
    Buffer.add_string buf (Printf.sprintf "X-Client-IP: %s\r\n" msg.client_ip);
    Buffer.add_string buf (Printf.sprintf "X-Client-Domain: %s\r\n" msg.client_domain);
    Buffer.add_string buf "\r\n";
    Buffer.add_string buf msg.data;
    Buffer.contents buf

  let deserialize_message content =
    (* Split into headers and body at blank line *)
    let header_end =
      match Str.search_forward (Str.regexp "\r\n\r\n") content 0 with
      | pos -> pos
      | exception Not_found ->
        match Str.search_forward (Str.regexp "\n\n") content 0 with
        | pos -> pos
        | exception Not_found -> String.length content
    in
    let headers_str = String.sub content 0 header_end in
    let body_start =
      if header_end + 4 <= String.length content &&
         String.sub content header_end 4 = "\r\n\r\n" then header_end + 4
      else if header_end + 2 <= String.length content then header_end + 2
      else String.length content
    in
    let data = String.sub content body_start (String.length content - body_start) in

    (* Parse headers *)
    let lines = Str.split (Str.regexp "\r?\n") headers_str in
    let id = ref "" in
    let sender = ref None in
    let recipients = ref [] in
    let received_at = ref 0.0 in
    let auth_user = ref None in
    let client_ip = ref "" in
    let client_domain = ref "" in

    List.iter (fun line ->
      if String.length line > 12 && String.sub line 0 12 = "X-Queue-Id: " then
        id := String.sub line 12 (String.length line - 12)
      else if String.length line > 10 && String.sub line 0 10 = "X-Sender: " then begin
        let s = String.sub line 10 (String.length line - 10) in
        sender := if s = "" || s = "<>" then None else parse_email_address s
      end
      else if String.length line > 13 && String.sub line 0 13 = "X-Recipient: " then begin
        let r = String.sub line 13 (String.length line - 13) in
        match parse_email_address r with
        | Some addr -> recipients := addr :: !recipients
        | None -> ()
      end
      else if String.length line > 15 && String.sub line 0 15 = "X-Received-At: " then
        received_at := float_of_string (String.sub line 15 (String.length line - 15))
      else if String.length line > 13 && String.sub line 0 13 = "X-Auth-User: " then
        auth_user := Some (String.sub line 13 (String.length line - 13))
      else if String.length line > 13 && String.sub line 0 13 = "X-Client-IP: " then
        client_ip := String.sub line 13 (String.length line - 13)
      else if String.length line > 17 && String.sub line 0 17 = "X-Client-Domain: " then
        client_domain := String.sub line 17 (String.length line - 17)
    ) lines;

    {
      id = !id;
      sender = !sender;
      recipients = List.rev !recipients;
      data;
      received_at = !received_at;
      auth_user = !auth_user;
      client_ip = !client_ip;
      client_domain = !client_domain;
    }

  let read_message_file path =
    try
      let ic = open_in_bin path in
      let len = in_channel_length ic in
      let content = really_input_string ic len in
      close_in ic;
      Some (deserialize_message content)
    with _ -> None

  let enqueue t msg =
    try
      ensure_dir t.base_path;
      let id = generate_queue_id () in
      let msg = { msg with id } in
      let path = message_path t id in
      let oc = open_out_bin path in
      output_string oc (serialize_message msg);
      close_out oc;
      t.index <- (id, path) :: t.index;
      Ok id
    with exn ->
      Error (Storage_error (Printexc.to_string exn))

  let dequeue t =
    match t.index with
    | [] -> None
    | (id, path) :: rest ->
      t.index <- rest;
      match read_message_file path with
      | Some msg -> Some { msg with id }
      | None -> None

  let peek t n =
    let rec take n acc = function
      | [] -> List.rev acc
      | _ when n <= 0 -> List.rev acc
      | (id, path) :: rest ->
        match read_message_file path with
        | Some msg -> take (n - 1) ({ msg with id } :: acc) rest
        | None -> take n acc rest
    in
    take n [] t.index

  let get _t ~id:_ =
    (* Would need to read and parse file *)
    None

  let mark_delivered t ~id =
    try
      let path = message_path t id in
      Unix.unlink path;
      t.index <- List.filter (fun (i, _) -> i <> id) t.index;
      Ok ()
    with exn ->
      Error (Storage_error (Printexc.to_string exn))

  let mark_failed t ~id ~reason:_ =
    (* Could move to a failed directory instead of deleting *)
    mark_delivered t ~id

  let get_stats t = {
    pending = List.length t.index;
    total_size = 0L;  (* Would need to stat files *)
  }
end
