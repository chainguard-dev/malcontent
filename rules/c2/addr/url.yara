import "math"

private rule elf_or_macho {
  condition:
    uint32(0) == 1179403647 or (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178)
}

rule unusual_nodename: medium {
  meta:
    description = "Contains HTTP hostname with a long node name"

  strings:
    $ref = /https*:\/\/\w{16,}\//

  condition:
    filesize < 5MB and $ref
}

rule exotic_tld: high {
  meta:
    description = "Contains HTTP hostname with unusual top-level domain"

  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker|ua|icu)\//
    $not_electron    = "ELECTRON_RUN_AS_NODE"
    $not_nips        = "nips.cc"
    $not_gov_bd      = ".gov.bd"
    $not_eol         = "endoflife.date"
    $not_whois       = "bdia.btcl.com.bd"
    $not_arduino     = "arduino.cc"

  condition:
    filesize < 10MB and any of ($http*) and none of ($not_*)
}

rule post_exotic_tld: high {
  meta:
    description = "uploads content to hostname with unusual top-level domain"

  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker|ua|icu)\//
    $post            = /(post|POST)/ fullword
    $not_electron    = "ELECTRON_RUN_AS_NODE"
    $not_nips        = "nips.cc"
    $not_gov_bd      = ".gov.bd"
    $not_eol         = "endoflife.date"
    $not_whois       = "bdia.btcl.com.bd"
    $not_arduino     = "arduino.cc"

  condition:
    filesize < 10MB and $http_exotic_tld and $post and none of ($not_*) and math.abs(@http_exotic_tld - @post) <= 128
}

rule http_url_with_question: medium {
  meta:
    description = "contains hardcoded endpoint with a question mark"

  strings:
    $f_import            = "import" fullword
    $f_require           = "require" fullword
    $f_curl              = "curl" fullword
    $f_wget              = "wget" fullword
    $f_requests          = "requests.get" fullword
    $f_requests_post     = "requests.post" fullword
    $f_urllib            = "urllib.request" fullword
    $f_urlopen           = "urlopen" fullword
    $f_fetch             = ".fetch("
    $f_get               = ".get("
    $ref                 = /https*:\/\/[\w\.\/]{8,160}\.[a-zA-Z]{2,3}[\w\/]{0,32}\?[\w\=\&]{0,32}/
    $not_cvs_sourceforge = /cvs.sourceforge.net.{0,64}\?rev=/
    $not_rev_head        = "?rev=HEAD"
    $not_cgi             = ".cgi?"
    $not_doku            = "/doku.php?"

  condition:
    filesize < 256KB and any of ($f*) and $ref and none of ($not*)
}

rule binary_with_url: low {
  meta:
    description = "binary contains hardcoded URL"
    filetypes   = "elf,macho"

  strings:
    $ref = /https*:\/\/[\w\.\/]{8,160}[\/\w\=\&]{0,32}/

  condition:
    filesize < 150MB and elf_or_macho and $ref
}

rule binary_url_with_question: high {
  meta:
    description = "binary contains hardcoded URL with question mark"
    filetypes   = "elf,macho"

  strings:
    $ref             = /https*:\/\/[\w\.\/]{8,160}\.(asp|php|exe|dll)\?[\w\=\&]{1,32}/
    $not_wikipedia   = "wikipedia.org/"
    $not_msdn        = "msdn.microsoft.com/"
    $not_codeproject = "www.codeproject.com/"
    $not_wiki        = "index.php?title="
    $not_mesibo      = "https://api.mesibo.com/api.php?"

  condition:
    filesize < 150MB and elf_or_macho and $ref and none of ($not*)
}

rule script_url_with_question: high {
  meta:
    description = "script contains hardcoded URL with question mark"

  strings:
    $f_import        = "import" fullword
    $f_require       = "require" fullword
    $f_curl          = "curl" fullword
    $f_wget          = "wget" fullword
    $f_requests      = "requests.get" fullword
    $f_requests_post = "requests.post" fullword
    $f_urllib        = "urllib.request" fullword
    $f_urlopen       = "urlopen" fullword
    $ref             = /https*:\/\/[\w\.\/]{8,160}\.(asp|php|exe|dll)\?[\w\=\&]{1,32}/

    $not_wikipedia   = "wikipedia.org/"
    $not_msdn        = "msdn.microsoft.com/"
    $not_codeproject = "www.codeproject.com/"
    $not_wiki        = "index.php?title="

  condition:
    filesize < 256KB and any of ($f*) and $ref and none of ($not*)
}

rule url_code_as_chr_int: high {
  meta:
    description = "hides URL within an array of integers"

  strings:
    $https  = "104,116,116,112,115,58,47,47"
    $https2 = "104, 116, 116, 112, 115, 58, 47, 47"
    $http   = "104,116,116,112,58,47,47"
    $http2  = "104, 116, 116, 112, 58, 47, 47"

  condition:
    filesize < 1MB and any of them
}
