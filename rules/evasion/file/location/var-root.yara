rule var_root_path: high macos {
  meta:
    description = "path reference within /var/root"

  strings:
    $ref = /\/var\/root\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}

rule known_var_root: override {
  meta:
    var_root_path = "medium"

  strings:
    $aonsensed         = "/var/root/BTRecord.csv"
    $iometrickitd      = "/var/root/mesa_calibration.bin"
    $internal_security = "com.apple.private.security."
    $internal_tcc      = "com.apple.private.tcc.allow"

  condition:
    any of them
}
