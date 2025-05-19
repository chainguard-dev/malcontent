rule echo_base64_decode: high {
  meta:
    description = "echo and decode base64 text"
    filetypes   = "bash,sh,zsh"

  strings:
    $ref = /echo [\w=\$]{2,256} {0,2}\| {0,2}base64 {0,2}(-d|--decode)/ fullword

  condition:
    filesize < 256KB and any of them
}
