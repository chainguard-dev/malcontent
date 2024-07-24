import "math"

rule python_exec_eval_one_line : critical {
  meta:
    description = "Evaluates code from encrypted content on a single line via exec or eval"
  strings:
    $f_eval_decrypt_one_line = /eval\s{0,32}\(.{0,32}decrypt/ ascii wide
    $f_exec_decrypt_one_line = /exec\s{0,32}\(.{0,32}decrypt/ ascii wide
    $not_opa = "constraintsdk_decision_eval"
    $not_opa2 = " (DEPRECATED: %s)decryption"
  condition:
    any of ($f*) and none of ($not*)
}

rule python_exec_near_enough_decrypt : high {
  meta:
    description = "Evaluates code from encrypted content"
    hash_2024_3web_1_0_0_setup = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"
    hash_2024_3web_py_1_0_0_setup = "fd74f0eecebb47178ef98ac9a744daaf982a16287c78fd9cb2fe9713f542f8c5"
    hash_2024_BeaitifulSoop_1_0_0_setup = "7b2a27e5d0559625fe7f6a4e0776130880130e414c851901bbfe0cdb892dadfe"
  strings:
    $exec = "exec(" fullword
    $decrypt = "decrypt(" fullword
  condition:
    all of them and math.abs(@decrypt - @exec) <= 256
}

rule python_exec_near_enough_fernet : critical {
  meta:
    description = "Evaluates code from encrypted content"
    hash_2024_3web_1_0_0_setup = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"
    hash_2024_3web_py_1_0_0_setup = "fd74f0eecebb47178ef98ac9a744daaf982a16287c78fd9cb2fe9713f542f8c5"
    hash_2024_BeaitifulSoop_1_0_0_setup = "7b2a27e5d0559625fe7f6a4e0776130880130e414c851901bbfe0cdb892dadfe"
  strings:
    $exec = "exec(" fullword
    $fernet = "Fernet"
  condition:
    all of them and math.abs(@fernet - @exec) <= 256
}
