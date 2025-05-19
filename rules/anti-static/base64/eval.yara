import "math"

rule eval_base64: high {
  meta:
    description = "Evaluates base64 content"
    filetypes   = "js,ts"

  strings:
    $eval = /eval\(.{0,256}base64/

  condition:
    any of them
}

rule ruby_eval_base64_decode: critical {
  meta:
    description = "Evaluates base64 content"
    filetypes   = "rb"

  strings:
    $eval_base64_decode = "eval(Base64."

  condition:
    any of them
}

rule ruby_eval_near_enough: high {
  meta:
    description = "Evaluates base64 content"
    filetypes   = "rb"

  strings:
    $eval   = "eval("
    $base64 = "Base64"

  condition:
    all of them and math.abs(@base64 - @eval) <= 128
}

rule ruby_eval2_near_enough: high {
  meta:
    description = "Evaluates base64 content"
    filetypes   = "rb"

  strings:
    $eval   = "eval("
    $base64 = "b64decode"

  condition:
    all of them and math.abs(@base64 - @eval) <= 200
}

rule python_exec_near_enough_base64: high {
  meta:
    description = "Likely executes base64 content"
    filetypes   = "py"

  strings:
    $exec   = "exec("
    $base64 = "b64decode"

  condition:
    all of them and math.abs(@base64 - @exec) < 200
}

rule python_base64_exec: critical {
  meta:
    description = "executes compressed base64 content"
    filetypes   = "py"

  strings:
    $dec_b64decode_exec = /.{0,8}\.decompress\(.{0,96}\.b64decode\(.{0,64}\Wexec\(.{0,16}/

  condition:
    any of them
}
