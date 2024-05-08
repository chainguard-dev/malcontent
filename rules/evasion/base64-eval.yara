import "math"

rule eval_base64 : suspicious {
  strings:
    $eval = /eval\(.{0,64}base64/
  condition:
    any of them
}

rule ruby_eval_base64_decode : critical {
  meta:
    description = "Evaluates base64 content"
  strings:
    $eval_base64_decode = "eval(Base64."
  condition:
    any of them
}

rule ruby_eval_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
  strings:
    $eval = "eval("
    $base64 = "Base64"
  condition:
    all of them and math.abs(@base64 - @eval) <= 128
}

rule ruby_eval2_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
  strings:
    $eval = "eval("
    $base64 = "b64decode"
  condition:
    all of them and math.abs(@base64 - @eval) <= 64
}

rule python_exec_near_enough : critical {
  meta:
    description = "Evaluates base64 content"
    hash_2023_UPX_7f5fd8c7cad4873993468c0c0a4cabdd8540fd6c2679351f58580524c1bfd0af_elf_x86_64 = "3b9f8c159df5d342213ed7bd5bc6e07bb103a055f4ac90ddb4b981957cd0ab53"
  strings:
    $exec = "exec("
    $base64 = "b64decode"
  condition:
    all of them and math.abs(@base64 - @exec) < 128
}

rule echo_decode_bash : suspicious {
  meta:
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_Unix_Trojan_Coinminer_3a6b = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
  strings:
    $echo = "echo" fullword
    $base64_decode = "base64 --decode"
    $base64_d = "base64 -d"
    $bash = "bash" fullword
    $sh = "sh" fullword
    $not_uucp = "UUCP" fullword
    $not_git = "git-core"
    $not_copyright = "Copyright (c)"
    $not_syntax = "syntax file"
  condition:
    filesize < 1048576 and $echo and ($bash or $sh) and ($base64_decode or $base64_d) and none of ($not*)
}
