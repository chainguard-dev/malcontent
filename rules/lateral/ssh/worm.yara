rule ssh_shell_worm: critical {
  meta:
    description = "SSH worm implemented in shell"

  strings:
    $dot_ssh = ".ssh" fullword

    $key_pem           = ".pem" fullword
    $key_rsa           = "id_rsa" fullword
    $key_identity_file = "IdentityFile" fullword

    $hosts_authorized_keys = "authorized_keys"
    $hosts_etc_hosts       = "/etc/hosts"
    $hosts_getent          = "getent ahostsv4"
    $hosts_ssh_config      = /grep.{1,8}HostName.{1,8}\/\.ssh\/config/
    $hosts_bash_history    = /(scp|ssh).{2,64}bash_history/
    $hosts_known_hosts     = "known_hosts"

    $remote_base64 = "base64"
    $remote_uname  = "uname"
    $remote_curl   = "curl -"
    $remote_wget   = "wget"
    $remote_lwp    = "lwp-download"

    $ssh_strict_host     = "StrictHostKeyChecking"
    $ssh_known_hosts     = "UserKnownHostsFile"
    $ssh_connect_timeout = "ConnectTimeout"

  condition:
    filesize < 32KB and $dot_ssh and 2 of ($ssh*) and 1 of ($remote*) and 3 of ($hosts*) and any of ($key*)
}

rule ssh_worm_router: high {
  meta:
    description = "ssh worm targeting routers"

  strings:
    $s_dot_ssh   = ".ssh"
    $h_etc_hosts = "/etc/hosts"
    $p_root123   = "root123"
    $p_passw0rd  = "Passw0rd"
    $p_admin123  = "admin123"
    $p_Admin123  = "Admin123"
    $p_qwerty123 = "qwerty123"

  condition:
    filesize < 1MB and all of ($s*) and any of ($h*) and 2 of ($p*)
}

