rule chmod_executable_shell: medium {
  meta:
    description = "makes file executable"

  strings:
    $val  = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $val2 = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
    $val3 = /chmod {1,4}-R {1,4}[04]{0,1}7[75][075] [ \$\@\w\/\.]{2,64}/

  condition:
    any of them
}

rule chmod_executable_binary: high {
  meta:
    description = "executable makes another file executable"
    filetypes   = "elf,macho"

  strings:
    $val         = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
    $val2        = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
    $val3        = /chmod {1,4}-R {1,4}[04]{0,1}7[75][075] [ \$\@\w\/\.]{2,64}/
    $not_example = "try 'chmod +x'"

  condition:
    filesize < 20MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and any of ($val*) and none of ($not*)
}

rule less_serious_chmod: override {
  meta:
    chmod_executable_binary = "medium"

  strings:
    $make_like = "chmod a+x $@"

  condition:
    any of them
}

rule chmod_executable_ruby: high {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"

  strings:
    $chmod_7_val = /File\.chmod\(\d{0,16}7\d{0,16}/

  condition:
    any of them
}

rule rename_executable_ruby: high windows {
  meta:
    description = "renames a file to become executable"

  strings:
    $rename = /File\.rename\(.{0,24}\w{0,8}\.exe\"\)/

  condition:
    any of them
}
