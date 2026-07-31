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
    $not_compdef         = "#compdef"
    $not_c1              = "/tmp/CaptureOne"
    $not_private_literal = "private-literal"
    $not_apple           = "Apple Inc"
    $not_sandbox         = "andbox profile"

    // Unlike the exclusions above, these two are themselves odd /tmp paths that
    // the references match, so naming one used to excuse every other odd /tmp
    // path in the file. They are counted instead of checked for presence.
    // $tmp_digits matches both, while $tmp_short only matches "/tmp/R8" (the
    // Brother path has too many characters before its digit), so each reference
    // is compared against just the accepted paths it can match.
    $notsub_brother = "/tmp/BroH9"
    $notsub_openra  = "/tmp/R8"

  condition:
    none of ($not_*) and (#tmp_digits > #notsub_brother + #notsub_openra or #tmp_short > #notsub_openra)
}
