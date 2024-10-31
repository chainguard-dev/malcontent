rule hex_parse_base64: critical {
  meta:
    description                  = "converts base64 hex data to ASCII"
    hash_2023_package_bgService  = "36831e715a152658bab9efbd4c2c75be50ee501b3dffdb5798d846a2259154a2"
    hash_2023_getcookies_harness = "99b1563adea48f05ff6dfffa17f320f12f0d0026c6b94769537a1b0b1d286c13"
    hash_1985_package_index      = "8d4daa082c46bfdef3d85a6b5e29a53ae4f45197028452de38b729d76d3714d1"

  strings:
    $lang_node   = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
    $lang_python = /\.unhexlify\(/
    $b_base64    = "base64"
    $b_b64decode = "b64decode"
    $exec_child  = "require('child_process')"

  condition:
    filesize < 32KB and any of ($lang*) and any of ($b*) and any of ($exec*)
}

