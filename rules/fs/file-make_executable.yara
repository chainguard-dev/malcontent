
rule chmod_executable_plus : notable {
  meta:
    description = "makes file executable"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
  strings:
    $val = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
  condition:
    $val
}

rule chmod_executable_octal : suspicious {
  meta:
    description = "makes file executable"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $val = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
  condition:
    $val
}

rule chmod_executable_ruby : suspicious {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    hash_2024_jumpcloud_init = "6acfc6f82f0fea6cc2484021e87fec5e47be1459e71201fbec09372236f8fc5a"
  strings:
    $chmod_7_val = /File\.chmod\(\d{0,16}7\d{0,16}/
  condition:
    any of them
}
