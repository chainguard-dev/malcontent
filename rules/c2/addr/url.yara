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

    $not_arduino = /https*:\/\/[\w\-\.]{0,128}arduino\.cc\//
    $not_eol     = /https*:\/\/[\w\-\.]{0,128}endoflife\.date\//
    $not_gov_bd  = /https*:\/\/[\w\-\.]{0,128}\.gov\.bd\//
    $not_nips    = /https*:\/\/[\w\-\.]{0,128}nips\.cc\//
    $not_whois   = /https*:\/\/[\w\-\.]{0,128}bdia\.btcl\.com\.bd\//

    $not_electron = "ELECTRON_RUN_AS_NODE"

  condition:
    // Every $not_* URL is a spelling $http_exotic_tld also matches, one match on each
    // side per URL, so compare occurrence counts: one accepted hostname must not mask
    // a second, unrelated exotic-TLD URL in the same file. The $not_* patterns carry
    // the scheme the reference requires so a bare hostname mention cannot suppress.
    // ELECTRON_RUN_AS_NODE names the bundling runtime, not a URL, and stays absolute.
    filesize < 10MB and $http_exotic_tld and #http_exotic_tld > #not_arduino + #not_eol + #not_gov_bd + #not_nips + #not_whois and not $not_electron
}

rule post_exotic_tld: high {
  meta:
    description = "uploads content to hostname with unusual top-level domain"

  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker|ua|icu)\//
    $post            = /(post|POST)/ fullword

    $not_arduino = /https*:\/\/[\w\-\.]{0,128}arduino\.cc\//
    $not_eol     = /https*:\/\/[\w\-\.]{0,128}endoflife\.date\//
    $not_gov_bd  = /https*:\/\/[\w\-\.]{0,128}\.gov\.bd\//
    $not_nips    = /https*:\/\/[\w\-\.]{0,128}nips\.cc\//
    $not_whois   = /https*:\/\/[\w\-\.]{0,128}bdia\.btcl\.com\.bd\//

    $not_electron = "ELECTRON_RUN_AS_NODE"

  condition:
    // Same accepted-URL set and counting rule as exotic_tld; the proximity term is
    // unaffected because it only compares the first $http_exotic_tld offset to $post.
    filesize < 10MB and $http_exotic_tld and $post and #http_exotic_tld > #not_arduino + #not_eol + #not_gov_bd + #not_nips + #not_whois and not $not_electron and math.abs(@http_exotic_tld - @post) <= 128
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
    // All four $not strings are fragments of a query-string URL that $ref matches, so
    // each accepted URL contributes one $ref match and at least one $not match.
    // Comparing counts means a single benign ".cgi?" endpoint no longer hides every
    // other query URL in the file; an unrelated bare mention only makes the guard more
    // conservative, never less.
    filesize < 256KB and any of ($f*) and $ref and #ref > #not_cvs_sourceforge + #not_rev_head + #not_cgi + #not_doku
}

rule binary_with_malicious_url: critical {
  meta:
    description = "binary contains hardcoded, malicious URL"
    filetypes   = "elf,macho"

  strings:
    $ = "https://mainnet.solana-rpc-pool.workers.dev"

  condition:
    filesize < 150MB and elf_or_macho and any of them
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
    // "index.php?title=" is a spelling of $ref itself, so count it instead of treating
    // it as absolute: one Wikipedia article link must not hide a second query URL. The
    // other three name the embedding project (a browser's search-provider table, a
    // secret scanner's detector table) rather than a URL $ref matches, so they stay
    // absolute.
    filesize < 150MB and elf_or_macho and $ref and #ref > #not_wiki and none of ($not_wikipedia, $not_msdn, $not_codeproject, $not_mesibo)
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
    // See binary_url_with_question: count the one string that is a spelling of $ref and
    // keep the project-identifying hostnames absolute.
    filesize < 256KB and any of ($f*) and $ref and #ref > #not_wiki and none of ($not_wikipedia, $not_msdn, $not_codeproject)
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
