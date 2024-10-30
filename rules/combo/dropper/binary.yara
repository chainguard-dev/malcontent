rule chmod_executable_shell_binary: high {
  meta:
    description = "executable makes another file executable"
    filetypes   = "macho,elf"

  strings:
    $chmod       = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $chmod2      = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
    $http        = "http:"
    $https       = "https:"
    $not_example = "try 'chmod +x'"

  condition:
    filesize < 10MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and any of ($chmod*) and any of ($http*) and none of ($not*)
}

rule download_and_execute: high {
  meta:
    description = "may download and execute a program"

  strings:
    $ref  = "download_and_execute"
    $ref2 = "download_and_exec"

  condition:
    filesize < 1MB and any of them
}
