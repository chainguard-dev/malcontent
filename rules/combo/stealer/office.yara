rule office_crypt_archive {
  meta:
    hash_2020_gonnacry = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
    hash_2022_DazzleSpy_agent_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
    hash_2020_GravityRat_enigma_py = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_OK_29c2 = "29c2f559a9494bce3d879aff8731a5d70a3789028055fd170c90965ce9cf0ea4"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
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
