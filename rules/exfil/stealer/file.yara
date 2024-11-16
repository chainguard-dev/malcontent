rule office_crypt_archive: high {
  meta:
    description = "Accesses Ofice documents, encrypts and archives"

  strings:
    $e_csv              = "csv" fullword
    $e_doc              = "doc" fullword
    $e_docm             = "docm" fullword
    $e_docx             = "docx" fullword
    $e_eml              = "eml" fullword
    $e_mov              = "mov" fullword
    $e_rtf              = "rtf" fullword
    $e_numbers          = "numbers" fullword
    $e_pages            = "pages" fullword
    $e_pdf              = "pdf" fullword
    $e_ppam             = "ppam" fullword
    $e_ppt              = "ppt" fullword
    $e_pst              = "pst" fullword
    $e_xls              = "xls" fullword
    $e_xlsx             = "xlsx" fullword
    $e_txt              = "txt" fullword
    $o_AES              = "AES"
    $o_base64           = "base64"
    $o_bash             = "/bin/bash"
    $o_cipher           = "cipher"
    $o_decrypt          = "decrypt"
    $o_documents        = "Documents"
    $o_encryptData      = "encryptData"
    $o_encrypt          = "Encrypt"
    $o_glob2            = "*.ppt"
    $o_glob             = "glob"
    $o_ioreg            = "ioreg -"
    $o_keychain         = "Keychain"
    $o_socks5           = "socks5"
    $o_unzip            = "unzip"
    $o_upload           = "upload" nocase
    $o_zip              = "zipFile"
    $not_kitty          = "KITTY_KITTEN"
    $not_prism          = "Prism.languages.xlsx"
    $not_xlsx_equal     = "xlsx="
    $not_private        = "/System/Library/PrivateFrameworks/"
    $not_program        = "@(#)PROGRAM:"
    $not_saving         = "saving"
    $not_audio_exits    = "audio_extensions"
    $not_filetypes      = "filetypes"
    $not_author_javadoc = "@author"
    $not_mime           = "application/vnd."
    $not_aifc           = "aifc"

  condition:
    filesize < 104857600 and ($e_xlsx or $e_docx) and 7 of ($e_*) and any of ($o_*) and none of ($not*)
}

rule sensitive_extensions: high {
  meta:
    description = "looks for files matching sensitive extensions"

  strings:
    $e_txt    = "rtf" fullword
    $e_doc    = "doc" fullword
    $e_docx   = "docx" fullword
    $e_xls    = "xls" fullword
    $e_xlsx   = "xlsx" fullword
    $e_key    = "key" fullword
    $e_wallet = "wallet" fullword
    $e_jpg    = "jpg" fullword
    $e_dat    = "dat" fullword
    $e_pdf    = "pdf" fullword
    $e_pem    = "pem" fullword
    $e_asc    = "asc" fullword
    $e_ppk    = "ppk" fullword
    $e_rdp    = "rdp" fullword
    $e_sql    = "sql" fullword
    $e_ovpn   = "ovpn" fullword
    $e_kdbx   = "kdbx" fullword
    $e_conf   = "conf" fullword
    $e_json   = "json" fullword

    $not_elf = "elf" fullword
    $not_zip = "dmg" fullword
    $not_pkg = "pkg" fullword

    $f_readdir = "readdir"
    $f_opendir = "opendir"

  condition:
    any of ($f*) and 85 % of ($e*) and none of ($not*)

}

rule curl_easy_exfil: high {
  meta:
    description = "possible filesystem exfiltration via curl_easy_init"

  strings:
    $curl    = "curl_easy_init" fullword
    $opendir = "opendir" fullword
    $readdir = "readdir" fullword
    $socket  = "socket" fullword
    $open    = "open" fullword
    $read    = "read" fullword

  condition:
    filesize < 1MB and all of them
}

