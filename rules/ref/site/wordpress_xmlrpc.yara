
rule wordpress_xmlrpc : suspicious {
  meta:
    description = "References xmlrpc.php from wordpress"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
  strings:
    $php_url = /[\w\/\.]{0,64}xmlrpc.php/
  condition:
    any of them
}
