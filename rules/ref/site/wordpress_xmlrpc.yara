
rule wordpress_xmlrpc : suspicious {
  meta:
    description = "References xmlrpc.php from wordpress"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2024_Downloads_8907 = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"
  strings:
    $php_url = /[\w\/\.]{0,64}xmlrpc.php/
  condition:
    any of them
}
