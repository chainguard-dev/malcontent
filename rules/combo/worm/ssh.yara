
rule ssh_snake_worm : suspicious {
  meta:
    description = "possible SSH worm like SSH-Snake"
  strings:
    $s_dot_ssh = ".ssh"
    $s_authorized_keys = "authorized_keys"
    $h_etc_hosts = "/etc/hosts"
    $h_getent = "getent ahostsv4"
    $u_base64 = "base64"
    $u_uname = "uname"
    $strict_host = "StrictHostKeyChecking"
    $user_known_hosts = "UserKnownHostsFile"
  condition:
    filesize < 67108864 and $strict_host and $user_known_hosts and all of ($s*) and any of ($h*) and any of ($u*)
}

rule ssh_worm_router : suspicious {
  meta:
    description = "ssh worm targetting routers"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
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
