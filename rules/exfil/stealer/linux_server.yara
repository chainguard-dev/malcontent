
rule linux_server_stealer : high {
  meta:
    description = "may steal sensitive Linux secrets"
    hash_2024_SSH_Snake = "b0a2bf48e29c6dfac64f112ac1cb181d184093f582615e54d5fad4c9403408be"
    hash_2022_services_api = "59c3ab81ea192e439bc39c5edbbc56518a80a0393e16d55fd5638a567dd96123"
    hash_2022_services_api = "fe617c77d66f0954d22d6488e4a481b0f8fdc9e3033fa23475dcd24e53561ec7"
  strings:
    $bash_history = ".bash_history"

    $other_root_ssh = "/root/.ssh"
    $other_id_rsa = ".ssh/id_rsa"
	$other_shadow = "etc/shadow"

	$term_crypto = "crypto" fullword
	$term_echo = "echo" fullword
	$term_chmod = "chmod" fullword
	$term_find = "find" fullword
	$term_scp = "scp" fullword
	$term_tar = "tar" fullword
	$term_crontab = "crontab" fullword
	$term_http = "http" fullword
  condition:
    filesize < 10MB and $bash_history and any of ($other*) and any of ($term*)
}
