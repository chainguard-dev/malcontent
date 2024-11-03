rule chmod_777_dropper: critical {
  meta:
    description = "transfers program, uses dangerous permissions, and possibly runs a binary"
    filetypes   = "macho,elf"

  strings:
    $chmod  = /chmod [\-\w ]{0,3}777 [ \$\@\w\/\.]{0,64}/
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
