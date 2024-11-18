rule linux_curl_easy_sysinfo: high {
  meta:
    description = "may use curl_easy to receive remote commands"

  strings:
    $curl_easy = "curl_easy"
    $fopen     = "fopen" fullword
    $fwrite    = "fwrite" fullword
    $system    = "system" fullword
    $unlink    = "unlink" fullword
    $chmod     = "chmod" fullword
    $https     = /https*:\/\/[\w\.\/]{4,32}/

  condition:
    filesize < 100KB and all of them
}
