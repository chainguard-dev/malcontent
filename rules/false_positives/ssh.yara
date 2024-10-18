rule sshd : override linux {
  meta:
    description = "sshd"
	login_records = "medium"
  strings:
	$auth = "SSH_USER_AUTH"
  condition:
    any of them
}
