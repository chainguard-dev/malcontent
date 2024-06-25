rule office_crypt_archive : high {
  meta:
	description = "Accesses Ofice documents, encrypts and archives"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_Downloads_f5de = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
  strings:
    $e_csv = "csv" fullword
    $e_doc = "doc" fullword
    $e_docm = "docm" fullword
    $e_docx = "docx" fullword
    $e_eml = "eml" fullword
    $e_mov = "mov" fullword
    $e_rtf = "rtf" fullword
    $e_numbers = "numbers" fullword
    $e_pages = "pages" fullword
    $e_pdf = "pdf" fullword
    $e_ppam = "ppam" fullword
    $e_ppt = "ppt" fullword
    $e_pst = "pst" fullword
    $e_xls = "xls" fullword
    $e_xlsx = "xlsx" fullword
    $e_txt = "txt" fullword

    $o_AES = "AES"
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
	$not_audio_exits = "audio_extensions"
	$not_filetypes = "filetypes"
	$not_author_javadoc = "@author"
	$not_mime = "application/vnd."
	$not_aifc = "aifc"
  condition:
    filesize < 104857600 and ($e_xlsx or $e_docx) and 7 of ($e_*) and any of ($o_*) and none of ($not*)
}
