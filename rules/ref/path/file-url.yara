
rule file_url {
  meta:
    hash_2022_DazzleSpy_agent_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
  strings:
    $file_private_url = "file:///private"
    $file_tmp_url = "file:///tmp"
    $file_var_url = "file:///var"
    $file_home_url = "file:///home"
    $file_users_url = "file:///Users"
	$not_file_socket = "file:///tmp/socket"
	$not_asl = "/var/log/asl"
  condition:
    any of ($file*) and none of ($not*)
}
