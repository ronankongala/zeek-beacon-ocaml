(* CASE-17: OCaml Zeek Beacon Detector
   Ported from CASE-18 (Python/Zeek/RITA).
   Reads Zeek conn.log TSV, groups connections by source IP,
   computes inter-arrival interval variance, and flags low-variance
   periodic senders as beacon candidates.

   Design notes vs. Python CASE-18:
   - Records replace dicts: invalid field access is a compile error, not a KeyError
   - List.fold_left replaces for-loops: state is explicit in the accumulator
   - Variant types (beacon_verdict) make "not scored yet" unrepresentable at runtime
   - No mutation in the scoring core: every transformation returns a new value *)

(* ── Types ──────────────────────────────────────────────────────────── *)

type conn_row = {
  ts       : float;    (* epoch seconds *)
  src_ip   : string;
  dst_ip   : string;
  dst_port : int;
  proto    : string;
  duration : float;
}

type beacon_verdict =
  | TooFewConns                      (* fewer than min_conns connections seen *)
  | HighVariance of float            (* variance above threshold *)
  | BeaconCandidate of {             (* low variance — possibly C2 *)
      mean_interval : float;
      variance      : float;
      conn_count    : int;
    }

type scored_ip = {
  ip      : string;
  verdict : beacon_verdict;
}

(* ── Parameters ──────────────────────────────────────────────────────── *)

let min_conns       = 5     (* require at least this many connections *)
let variance_thresh = 5.0   (* seconds²; flag as beacon if below this *)

(* ── Parsing ─────────────────────────────────────────────────────────── *)

(* Zeek conn.log header lines start with '#'; data lines are TSV.
   Field order (default Zeek conn.log):
   0:ts  1:uid  2:id.orig_h  3:id.orig_p  4:id.resp_h  5:id.resp_p
   6:proto  7:service  8:duration  9:orig_bytes  10:resp_bytes ...   *)
let parse_line line =
  if String.length line = 0 || line.[0] = '#' then None
  else
    match String.split_on_char '\t' line with
    | ts :: _uid :: src_ip :: _src_p :: dst_ip :: dst_port_s
      :: proto :: _service :: duration_s :: _ ->
      (try
        Some {
          ts       = float_of_string ts;
          src_ip;
          dst_ip;
          dst_port = int_of_string dst_port_s;
          proto;
          duration = (if duration_s = "-" then 0.0
                      else float_of_string duration_s);
        }
      with Failure _ -> None)   (* malformed field — skip row *)
    | _ -> None

let load_conn_log path =
  let ic  = open_in path in
  let acc = ref [] in
  (try
    while true do
      let line = input_line ic in
      match parse_line line with
      | Some row -> acc := row :: !acc
      | None     -> ()
    done
  with End_of_file -> ());
  close_in ic;
  List.rev !acc

(* ── Grouping ────────────────────────────────────────────────────────── *)

module StrMap = Map.Make (String)

(* Group rows by src_ip using a balanced BST map — O(n log k) total,
   where k = number of unique source IPs. *)
let group_by_src rows =
  List.fold_left
    (fun acc row ->
      let bucket =
        match StrMap.find_opt row.src_ip acc with
        | Some xs -> xs
        | None    -> []
      in
      StrMap.add row.src_ip (row :: bucket) acc)
    StrMap.empty
    rows

(* ── Statistics — purely functional ────────────────────────────────── *)

let mean lst =
  let n = List.length lst in
  if n = 0 then 0.0
  else List.fold_left ( +. ) 0.0 lst /. float_of_int n

let variance lst =
  let m        = mean lst in
  let sq_diffs = List.map (fun x -> let d = x -. m in d *. d) lst in
  mean sq_diffs

(* Compute pairwise inter-arrival intervals from a sorted timestamp list. *)
let intervals ts_list =
  let rec go acc = function
    | []                    -> List.rev acc
    | [_]                   -> List.rev acc
    | a :: (b :: _ as rest) -> go ((b -. a) :: acc) rest
  in
  go [] ts_list

(* ── Scoring ─────────────────────────────────────────────────────────── *)

let score_ip ip rows =
  let ts =
    rows
    |> List.map (fun r -> r.ts)
    |> List.sort compare
  in
  let n = List.length ts in
  if n < min_conns then
    { ip; verdict = TooFewConns }
  else
    let ivs = intervals ts in
    let v   = variance ivs in
    if v > variance_thresh then
      { ip; verdict = HighVariance v }
    else
      { ip; verdict = BeaconCandidate {
          mean_interval = mean ivs;
          variance      = v;
          conn_count    = n;
        }}

(* ── Output ──────────────────────────────────────────────────────────── *)

let pp_verdict = function
  | TooFewConns ->
    "TOO_FEW_CONNS"
  | HighVariance v ->
    Printf.sprintf "HIGH_VARIANCE (var=%.2f)" v
  | BeaconCandidate { mean_interval; variance; conn_count } ->
    Printf.sprintf "BEACON_CANDIDATE  interval=%.1fs  var=%.2f  conns=%d"
      mean_interval variance conn_count

let print_results scored =
  let candidates = List.filter
    (fun s -> match s.verdict with BeaconCandidate _ -> true | _ -> false)
    scored
  in
  (* Beacon candidates sorted by ascending variance: lowest = most suspicious. *)
  let sorted_candidates = List.sort
    (fun a b -> match a.verdict, b.verdict with
      | BeaconCandidate x, BeaconCandidate y -> compare x.variance y.variance
      | _ -> 0)
    candidates
  in
  let non_candidates = List.filter
    (fun s -> match s.verdict with BeaconCandidate _ -> false | _ -> true)
    scored
  in
  Printf.printf "%-20s  %s\n" "src_ip" "verdict";
  Printf.printf "%s\n" (String.make 70 '-');
  (* Candidates first, then all other scored IPs for context. *)
  List.iter
    (fun s -> Printf.printf "%-20s  %s\n" s.ip (pp_verdict s.verdict))
    (sorted_candidates @ non_candidates);
  Printf.printf "\n%d beacon candidate(s) from %d scored IPs\n"
    (List.length candidates) (List.length scored)

(* ── Entry point ─────────────────────────────────────────────────────── *)

let () =
  let path =
    if Array.length Sys.argv > 1 then Sys.argv.(1)
    else (print_endline "usage: beacon.exe <conn.log>"; exit 1)
  in
  Printf.printf "Loading %s ...\n%!" path;
  let rows   = load_conn_log path in
  Printf.printf "Parsed %d connection rows\n\n%!" (List.length rows);
  let groups = group_by_src rows in
  let scored =
    StrMap.fold (fun ip bucket acc -> score_ip ip bucket :: acc) groups []
    |> List.rev
  in
  print_results scored
