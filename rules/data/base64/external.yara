rule base64_shell_decode: medium {
  meta:
    description = "calls base64 command to decode strings"

  strings:
    $base64_d          = "base64 -d"
    $base64_d_b64      = "base64 -d" base64
    $base64_D          = "base64 -D"
    $base64_D_b64      = "base64 -D" base64
    $base64_decode     = "base64 --decode"
    $base64_decode_b64 = "base64 --decode" base64
    $base64_re         = /base64 [\w\%\@\- ]{0,16} -[dD]/
    $not_example       = "base64 --decode | keybase"

  condition:
    // "base64 --decode | keybase" contains no other accepted spelling, so it can
    // only excuse a $base64_decode match: the remaining spellings still fire on
    // their own, and a "base64 --decode" beyond the keybase line still counts.
    any of ($base64_d, $base64_d_b64, $base64_D, $base64_D_b64, $base64_decode_b64, $base64_re) or #base64_decode > #not_example
}

rule base64_shell_encode: medium {
  meta:
    description = "calls base64 command to encode strings"

  strings:
    $base64_pipe = /\| {0,2}base64/
    $base64_w    = "base64 -w"

  condition:
    any of them
}

rule base64_shell_double_encode: critical {
  meta:
    description = "calls base64 command to double-encode strings"

  strings:
    $ref = /base64[\s>].{0,32}\|\s{0,2}base64/

    $not_gpgme   = "if (!base64 || base64 == -1) /* Make sure that we really have a string.  */"
    $not_unix_rb = "echo '%<base64>s' | base64 --decode > %<file>s"

  // $ref matches once inside each accepted line ("base64 || base64" in gpgme,
  // "%<base64>s' | base64" in the Ruby template), so their presence used to
  // excuse the whole file. Compare occurrence counts instead: fire only on a
  // double-encode $ref match neither accepted line accounts for.

  condition:
    $ref and #ref > #not_gpgme + #not_unix_rb
}
