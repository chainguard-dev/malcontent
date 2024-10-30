rule chmod_executable_shell: medium {
  meta:
    description                                                                          = "makes file executable"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35                                                             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929                                                             = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $val  = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $val2 = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/

  condition:
    any of them
}

rule chmod_executable_shell_binary: high {
  meta:
    description = "executable makes another file executable"
    filetypes   = "macho,elf"

  strings:
    $val         = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $val2        = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
    $not_example = "try 'chmod +x'"

  condition:
    filesize < 20MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and any of ($val*) and none of ($not*)
}

rule chmod_executable_ruby: high {
  meta:
    jumpcloud                = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    hash_2024_jumpcloud_init = "6acfc6f82f0fea6cc2484021e87fec5e47be1459e71201fbec09372236f8fc5a"

  strings:
    $chmod_7_val = /File\.chmod\(\d{0,16}7\d{0,16}/

  condition:
    any of them
}
