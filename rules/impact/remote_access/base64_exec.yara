rule hex_convert_base64_ascii: high {
  meta:
    description = "executes programs, converts base64 hex data to ASCII"

  strings:
    $lang_node   = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
    $lang_python = /\.unhexlify\(/
    $b_base64    = "base64"
    $b_b64decode = "b64decode"
    $exec_child  = "require('child_process')"

  condition:
    filesize < 32KB and any of ($lang*) and any of ($b*) and any of ($exec*)
}

