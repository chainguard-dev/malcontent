import "math"

rule exfil_libcurl_elf: high linux {
  meta:
    pledge      = "inet"
    description = "obfuscated binary may exfiltrate data"
    sha256      = "caa69b10b0bfca561dec90cbd1132b6dcb2c8a44d76a272a0b70b5c64776ff6c"
    ref         = "https://www.uptycs.com/blog/threat-research-report-team/new-poc-exploit-backdoor-malware"
    filetypes   = "application/x-elf"

  strings:
    $f_curl_easy      = "curl_easy_init" fullword
    $f_fopen          = "fopen" fullword
    $f_ftruncate      = "ftruncate" fullword
    $f_fork           = "fork" fullword
    $f_realloc        = "realloc" fullword
    $f_getpid         = "getpid" fullword
    $f_chmod          = "chmod" fullword
    $f_flock          = "flock" fullword
    $f_feof           = "feof" fullword
    $f_strlen         = "strlen" fullword
    $f_getenv         = "getenv" fullword
    $f_system         = "system" fullword
    $f_readlink       = "readlink" fullword
    $f_fwrite         = "fwrite" fullword
    $f_fread          = "fread" fullword
    $f_fprintf        = "fprintf" fullword
    $f_utime          = "utime" fullword
    $f_sleep          = "sleep" fullword
    $word_with_spaces = /[a-z]{2,16} [a-uxyz]{2,16}/ fullword

  condition:
    filesize < 32KB and all of ($f*) and #word_with_spaces <= 1 and math.entropy(3000, filesize) > 3
}
