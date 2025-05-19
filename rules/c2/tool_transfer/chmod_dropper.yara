rule chmod_77x_dropper: critical {
  meta:
    description = "transfers program, uses dangerous permissions, and possibly runs a binary"
    filetypes   = "elf,macho"

  strings:
    $chmod  = /chmod [\-\w ]{0,3}77[750] [ \$\@\w\/\.]{0,64}/
    $t_wget = "wget" fullword
    $t_curl = "curl" fullword
    $t_tftp = "tftp" fullword

    $o_dotslash = /\.\/[\.\$\w]{0,16}/
    $o_rm       = /rm -[rR]{0,1}f/
    $o_tmp      = "/tmp/"
    $o_dev      = "/dev/"

  condition:
    filesize < 1KB and $chmod and any of ($t*) and any of ($o*)
}

rule chmod_executable_shell_binary: high {
  meta:
    description = "executable makes another file executable"
    filetypes   = "elf,macho"

  strings:
    $chmod       = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $chmod2      = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
    $http        = "http://"
    $https       = "https://"
    $not_example = "try 'chmod +x'"
    $not_make    = "chmod a+x $@"

  condition:
    filesize < 10MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and any of ($chmod*) and any of ($http*) and none of ($not*)
}
