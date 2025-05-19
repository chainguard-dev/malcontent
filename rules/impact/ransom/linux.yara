rule encrypter: high {
  meta:
    description = "probable Linux ransomware encrypter"

  strings:
    $ENCRYPTER = "ENCRYPTER"
    $Encrypter = "Encrypter"
    $f_readdir = "readdir"
    $f_fopen   = "fopen"
    $f_pthread = "pthread"

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and any of ($E*) and all of ($f*)
}

rule esxi_chacha: high {
  meta:
    description = "probable Linux ransomware encrypter"

  strings:
    $E_esxi    = "esxi" fullword
    $E_chacha  = "chacha20" fullword
    $f_readdir = "readdir"
    $f_fopen   = "fopen"
    $f_pthread = "pthread"

  condition:
    filesize < 128KB and uint32(0) == 1179403647 and any of ($E*) and all of ($f*)
}

rule linux_syscalls: high {
  meta:
    description = "possible Linux ransomware encrypter"

  strings:
    $e_Encrypt     = "ENCRYPT"
    $e_encrypt     = "encrypt"
    $e_chacha      = "chacha20"
    $e_Processed   = "Processed:"
    $e_total_files = "Total files"
    $e_esxi        = "esxi" fullword
    $e_vmsvc       = "vmscvc" fullword

    $f_fork     = "fork" fullword
    $f_popen    = "popen" fullword
    $f_strcpy   = "strcpy" fullword
    $f_closedir = "closedir" fullword
    $f_readdir  = "readdir" fullword
    $f_fopen    = "fopen" fullword
    $f_pthread  = "pthread" fullword
    $f_feof     = "feof" fullword
    $f_opendir  = "opendir" fullword
    $f_seek     = "fseek" fullword
    $f_read     = "fread" fullword
    $f_rename   = "rename" fullword
    $f_atoi     = "atoi" fullword

    $not_getgid     = "getgid" fullword
    $not_strtol     = "strtol" fullword
    $not_dlopen     = "dlopen" fullword
    $not_setenv     = "setenv" fullword
    $not_asctime    = "asctime" fullword
    $not_inet_ntop  = "inet_ntop" fullword
    $not_getifaddrs = "getifaddrs" fullword

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and $f_readdir and 85 % of ($f*) and any of ($e*) and none of ($not*)
}

rule conti_alike: high posix {
  meta:
    description = "Reads directories, renames files, encrypts files"
    filetypes   = "elf,macho,so"

  strings:
    $readdir       = "readdir" fullword
    $rename        = "rename" fullword
    $enc1          = "encrypted by"
    $enc2          = "RSA PUBLIC KEY"
    $enc3          = "Encrypting file"
    $enc4          = "files_encrypted"
    $enc5          = "encrypts files"
    $enc6          = "ENCRYPTER"
    $not_fscrypt_h = "#define _LINUX_FSCRYPT_H"

  condition:
    filesize < 512KB and $readdir and $rename and 2 of ($enc*) and none of ($not*)
}
