rule file_url {
  strings:
    $file_private_url = "file:///private"
    $file_tmp_url     = "file:///tmp"
    $file_var_url     = "file:///var"
    $file_home_url    = "file:///home"
    $file_users_url   = "file:///Users"
    $not_file_socket  = "file:///tmp/socket"
    $not_asl          = "/var/log/asl"

  // $file_tmp_url is a prefix of $not_file_socket, so one benign socket URL used
  // to exempt every other file:/// URL in the file. Compare occurrence counts
  // instead: fire only on a file:/// URL the socket URLs do not account for.
  // $not_asl stands on its own and stays a plain presence check.

  condition:
    any of ($file*) and #file_private_url + #file_tmp_url + #file_var_url + #file_home_url + #file_users_url > #not_file_socket and not $not_asl
}
