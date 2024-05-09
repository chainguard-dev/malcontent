
rule office_crypt_archive : high {
  meta:
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2023_Downloads_f5de = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
  strings:
    $e_csv = "csv" fullword
    $e_doc = "doc" fullword
    $e_docm = "docm" fullword
    $e_docx = "docx" fullword
    $e_eml = "eml" fullword
    $e_jpg = "jpg" fullword
    $e_mov = "mov" fullword
    $e_rtf = "rtf" fullword
    $e_mp4 = "mp4" fullword
    $e_numbers = "numbers" fullword
    $e_pages = "pages" fullword
    $e_pdf = "pdf" fullword
    $e_ppam = "ppam" fullword
    $e_ppt = "ppt" fullword
    $e_pst = "pst" fullword
    $e_xls = "xls" fullword
    $e_xlsx = "xlsx" fullword
    $e_txt = "txt" fullword
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_osquery = "OSQUERY_WORKER"
    $not_vcse = "CORINFO_HELP"
    $not_ab = "This is ApacheBench"
    $not_xul = "XUL_APP_FILE"
    $o_AES = "AES."
    $o_base64 = "base64"
    $o_bash = "/bin/bash"
    $o_cipher = "cipher"
    $o_decrypt = "decrypt"
    $o_documents = "Documents"
    $o_encryptData = "encryptData"
    $o_encrypt = "Encrypt"
    $o_glob2 = "*.ppt"
    $o_glob = "glob"
    $o_ioreg = "ioreg -"
    $o_keychain = "Keychain"
    $o_socks5 = "socks5"
    $o_unzip = "unzip"
    $o_upload = "upload" nocase
    $o_zip = "zipFile"
    $not_kitty = "KITTY_KITTEN"
    $not_prism = "Prism.languages.xlsx"
    $not_xlsx_equal = "xlsx="
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_program = "@(#)PROGRAM:"
    $not_saving = "saving"
  condition:
    filesize < 104857600 and ($e_xlsx or $e_docx) and 7 of ($e_*) and any of ($o_*) and none of ($not*)
}
