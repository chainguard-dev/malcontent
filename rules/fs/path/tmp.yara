rule tmp_path: medium {
  meta:
    description = "path reference within /tmp"

  strings:
    $resolv = /\/tmp\/[%\w\.\-\/]{0,64}/

  condition:
    any of them
}

rule weird_tmp_path_not_hidden: medium {
  meta:
    description = "references an unusual path within /tmp"

  strings:
    $tmp_digits          = /\/tmp\/[\w]*\d{1,128}/
    $tmp_short           = /\/tmp\/[\w\.\-]{1,3}[^\w\.\-]/
    $not_x11             = "/tmp/.X11"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_movie           = "/tmp/myTestMovie.m4"
    $not_usage           = "usage: "
    $not_invalid         = "invalid command option"
    $not_brother         = "/tmp/BroH9"
    $not_compdef         = "#compdef"
    $not_c1              = "/tmp/CaptureOne"
    $not_openra          = "/tmp/R8"
    $not_private_literal = "private-literal"
    $not_apple           = "Apple Inc"
    $not_sandbox         = "andbox profile"

  condition:
    any of ($t*) and none of ($not*)
}
