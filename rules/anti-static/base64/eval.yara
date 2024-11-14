import "math"

rule eval_base64: high {
  meta:
    hash_2023_0xShell = "acf556b26bb0eb193e68a3863662d9707cbf827d84c34fbc8c19d09b8ea811a1"

    hash_2023_0xShell = "a6f1f9c9180cb77952398e719e4ef083ccac1e54c5242ea2bc6fe63e6ab4bb29"

  strings:
    $eval = /eval\(.{0,256}base64/

  condition:
    any of them
}

rule ruby_eval_base64_decode: critical {
  meta:
    description = "Evaluates base64 content"

  strings:
    $eval_base64_decode = "eval(Base64."

  condition:
    any of them
}

rule ruby_eval_near_enough: critical {
  meta:
    description = "Evaluates base64 content"

    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"

  strings:
    $eval   = "eval("
    $base64 = "Base64"

  condition:
    all of them and math.abs(@base64 - @eval) <= 128
}

rule ruby_eval2_near_enough: critical {
  meta:
    description = "Evaluates base64 content"

  strings:
    $eval   = "eval("
    $base64 = "b64decode"

  condition:
    all of them and math.abs(@base64 - @eval) <= 200
}

rule python_exec_near_enough: high {
  meta:
    description = "Evaluates base64 content"

    hash_2019_CookieMiner_OAZG = "27ccebdda20264b93a37103f3076f6678c3446a2c2bfd8a73111dbc8c7eeeb71"
    hash_2018_EvilOSX_89e5     = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"

  strings:
    $exec   = "exec("
    $base64 = "b64decode"

  condition:
    all of them and math.abs(@base64 - @exec) < 200
}

rule echo_decode_bash_probable: high {
  meta:
    description          = "likely pipes base64 into a shell"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"

  strings:
    $echo          = "echo" fullword
    $base64_decode = "base64 --decode"
    $base64_d      = "base64 -d"
    $bash          = "bash" fullword
    $sh            = "sh" fullword
    $not_uucp      = "UUCP" fullword
    $not_git       = "git-core"
    $not_copyright = "Copyright (c)"
    $not_syntax    = "syntax file"

  condition:
    filesize < 15KB and $echo and ($bash or $sh) and ($base64_decode or $base64_d) and none of ($not*)
}

rule acme_sh: override {
  meta:
    description               = "acme.sh"
    echo_decode_bash_probable = "medium"
    iplookup_website          = "medium"

  strings:
    $ref = "https://github.com/acmesh-official"

  condition:
    $ref
}

rule echo_decode_bash: critical {
  meta:
    description = "executes base64 encoded shell commands"

  strings:
    $bash = /[\w=\$]{0,8} ?\| ?base64 -d[ecod]{0,5} ?\| ?bash/
    $sh   = /[\w=\$]{0,8} ?\| ?base64 -d[ecod]{0,5} ?\| ?z?sh/

  condition:
    filesize < 64KB and any of them
}
