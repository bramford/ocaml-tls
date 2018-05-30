let connect host port ca_dir cipher =
  let%lwt authenticator = X509_lwt.authenticator (`Ca_dir ca_dir) in
  try%lwt
    let%lwt ic, oc =
      Tls_lwt.connect_ext
        (Tls.Config.client
           ~authenticator:authenticator
           ~ciphers:[cipher]
           ()
        )
        (host, port)
    in
    let%lwt () =
      Lwt_io.eprintf
        "%sCIPHER SUCCESS: %s\n%!"
        (if Tls.Ciphersuite.ciphersuite_tls12_only cipher then "TLS1.2 " else "       ")
        (Tls.Ciphersuite.ciphersuite_to_string cipher)
    in
    Lwt.return ()
  with
  | Tls_lwt.Tls_alert Tls.Packet.HANDSHAKE_FAILURE ->
      Lwt_io.eprintf
        "%sCIPHER FAILURE: %s\n%!"
        (if Tls.Ciphersuite.ciphersuite_tls12_only cipher then "TLS1.2 " else "       ")
        (Tls.Ciphersuite.ciphersuite_to_string cipher)
  | Tls_lwt.Tls_alert alert as exn ->
      Printf.eprintf "OTHER REMOTE FAILURE: %s\n%!"
      (Tls.Packet.alert_type_to_string alert)
      ; raise exn
  | Tls_lwt.Tls_failure fail as exn ->
      Printf.eprintf "OTHER LOCAL FAILURE: %s\n%!"
      (Tls.Engine.string_of_failure fail)
      ; raise exn

let () =
  let ciphers = Tls.Config.Ciphers.supported in
  let host = "remoteok.io" in
  let port = 443 in
  let ca_dir = "/etc/ssl/certs" in
  let tests =
    Lwt_list.iter_p
      (fun cipher -> connect host port ca_dir cipher)
      ciphers
  in
  Lwt_main.run tests
