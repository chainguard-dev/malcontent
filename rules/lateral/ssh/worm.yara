
rule ssh_shell_worm : critical {
  meta:
    description = "SSH worm implemented in shell"
	hash_2024_SSH_Snake_Snake_nocomments = "9491fa95f40a69f27ce99229be636030fdc49f315cb9c897db3b602c34a8ceda"
    hash_2024_SSH_Snake = "b0a2bf48e29c6dfac64f112ac1cb181d184093f582615e54d5fad4c9403408be"
  strings:
    $dot_ssh = ".ssh" fullword

	$key_pem = ".pem" fullword
	$key_rsa = "id_rsa" fullword
	$key_identity_file = "IdentityFile" fullword

    $hosts_authorized_keys = "authorized_keys"
    $hosts_etc_hosts = "/etc/hosts"
    $hosts_getent = "getent ahostsv4"
	$hosts_ssh_config = /grep.{1,8}HostName.{1,8}\/\.ssh\/config/
	$hosts_bash_history = /(scp|ssh).{2,64}bash_history/
	$hosts_known_hosts = "known_hosts"

    $remote_base64 = "base64"
    $remote_uname = "uname"
	$remote_curl = "curl -"
	$remote_wget = "wget"
	$remote_lwp = "lwp-download"

    $ssh_strict_host = "StrictHostKeyChecking"
    $ssh_known_hosts = "UserKnownHostsFile"
	$ssh_connect_timeout = "ConnectTimeout"
  condition:
    filesize < 32KB and $dot_ssh and 2 of ($ssh*) and 1 of ($remote*) and 3 of ($hosts*) and any of ($key*)
}

rule ssh_worm_router : high {
  meta:
    description = "ssh worm targeting routers"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
  strings:
    $s_dot_ssh = ".ssh"
    $h_etc_hosts = "/etc/hosts"
    $p_root123 = "root123"
    $p_passw0rd = "Passw0rd"
    $p_admin123 = "admin123"
    $p_Admin123 = "Admin123"
    $p_qwerty123 = "qwerty123"
  condition:
    all of ($s*) and any of ($h*) and any of ($p*)
}


