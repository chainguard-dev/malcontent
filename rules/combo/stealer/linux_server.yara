rule linux_server_stealer : high {
  strings:
	$bash_history = ".bash_history"
	$root_ssh = "/root/.ssh"
	$id_rsa = ".ssh/id_rsa"
  condition:
	$bash_history and ($root_ssh or $id_rsa)
}
