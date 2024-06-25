
rule ssh_snake_worm : high {
  meta:
    description = "possible SSH worm like SSH-Snake"
    hash_2024_SSH_Snake_Snake_nocomments = "9491fa95f40a69f27ce99229be636030fdc49f315cb9c897db3b602c34a8ceda"
    hash_2024_SSH_Snake = "b0a2bf48e29c6dfac64f112ac1cb181d184093f582615e54d5fad4c9403408be"
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

rule ssh_worm_router : high {
  meta:
    description = "ssh worm targetting routers"
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
