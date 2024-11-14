import "math"

rule eval_base64: high {
  meta:
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

    hash_2018_EvilOSX_89e5 = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"

  strings:
    $exec   = "exec("
    $base64 = "b64decode"

  condition:
    all of them and math.abs(@base64 - @exec) < 200
}

rule echo_decode_bash_probable: high {
  meta:
    description = "likely pipes base64 into a shell"

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
