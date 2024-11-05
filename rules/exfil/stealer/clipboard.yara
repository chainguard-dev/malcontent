rule pyperclip_stealer: high {
  meta:
    description = "may steal clipboard contents"

  strings:
    $import         = "import" fullword
    $clip           = "pyperclip" fullword
    $http_urllib    = "urllib" fullword
    $http_urlopen   = "urlopen" fullword
    $http_requests  = "requests" fullword
    $other_base64   = "base64" fullword
    $other_tempfile = "tempfile" fullword
    $other_zipfile  = "zipfile" fullword
    $other_cipher   = "Crypto.Cipher" fullword
    $other_gzip     = "gzip" fullword
    $other_lzma     = "lzma" fullword
    $other_crypt    = "CryptUnprotectData" fullword

  condition:
    filesize < 1MB and $clip and $import and any of ($http*) and any of ($other*)
}
