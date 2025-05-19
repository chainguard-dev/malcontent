rule blankOBF: critical {
  meta:
    description = "packed with https://github.com/Blank-c/BlankOBF"
    filetypes   = "py"

  strings:
    $obfus  = "Obfuscated with BlankOBF"
    $eval   = /_{1,32}=eval\(\"\\x\d{1,3}/
    $decode = /_{1,32}=_{1,32}.decode\(\)/
    $return = /return \(_{1,32},_{1,32}\)/
    // \"\\x\d2.{0,32}/
    $def    = /def _{1,64}\(_{1,64},/

  condition:
    filesize < 1MB and any of them
}
