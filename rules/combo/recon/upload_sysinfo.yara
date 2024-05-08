
rule sw_vers_and_libcurl : notable {
  meta:
    description = "fetches macOS system version and uses libcurl"
  strings:
    $sw_vers = "sw_vers" fullword
    $bin_zsh = "libcurl"
  condition:
    all of them
}
