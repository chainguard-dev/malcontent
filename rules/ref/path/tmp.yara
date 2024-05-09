
rule tmp_path : medium {
  meta:
    description = "path reference within /tmp"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2019_test_sprockets_rails_test = "6c50a21a69f2bcb27a55e909f9fecd4a7bd7fc0898730d1c76e65b2a7172710b"
    hash_2019_support_dummy_rails_integration = "b21b9b7fb250558c3340d9d8f11aab5f1c448628a703f14a21db5dbe4ec78520"
  strings:
    $resolv = /\/tmp\/[%\w\.\-\/]{0,64}/
  condition:
    any of them
}

rule weird_tmp_path_not_hidden : medium {
  meta:
    description = "references an unusual path within /tmp"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
  strings:
    $tmp_digits = /\/tmp\/[\w]*\d{1,128}/
    $tmp_short = /\/tmp\/[\w\.\-]{1,3}[^\w\.\-]/
    $not_x11 = "/tmp/.X11"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_movie = "/tmp/myTestMovie.m4"
    $not_usage = "usage: "
    $not_invalid = "invalid command option"
    $not_brother = "/tmp/BroH9"
    $not_compdef = "#compdef"
    $not_c1 = "/tmp/CaptureOne"
    $not_openra = "/tmp/R8"
    $not_private_literal = "private-literal"
    $not_apple = "Apple Inc"
    $not_sandbox = "andbox profile"
  condition:
    any of ($t*) and none of ($not*)
}
