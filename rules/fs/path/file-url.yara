rule file_url {
  strings:
    $file_private_url = "file:///private"
    $file_tmp_url     = "file:///tmp"
    $file_var_url     = "file:///var"
    $file_home_url    = "file:///home"
    $file_users_url   = "file:///Users"
    $not_file_socket  = "file:///tmp/socket"
    $not_asl          = "/var/log/asl"

  condition:
    any of ($file*) and none of ($not*)
}
