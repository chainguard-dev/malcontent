rule https_url {
  meta:
    description = "contains embedded HTTPS URLs"

  strings:
    $ref       = /https:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $not_apple = "https://www.apple.com/appleca/"

  condition:
    $ref and none of ($not*)
}

rule http_url {
  meta:
    description = "contains embedded HTTP URLs"

  strings:
    $ref       = /http:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $not_apple = "http://crl.apple.com/"

  condition:
    $ref and none of ($not*)
}

rule ftp_url {
  meta:
    description = "contains embedded FTP URLs"

  strings:
    $ref = /ftp:\/\/[\w][\w\.\/\-_]{8,64}/

  condition:
    any of them
}

rule ssh_url {
  meta:
    description = "contains embedded URLs"

  strings:
    $ref = /ssh:\/\/[\w][\w\.\/\-_]{8,64}/

  condition:
    any of them
}

rule http_url_with_php: medium {
  meta:
    description               = "contains hardcoded PHP endpoint"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"

  strings:
    $php_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.php/
    $php_question = /[\.\w\-\_\/:]{0,160}\.php\?[\w\-@\=]{0,32}/
    $php_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.php/

  condition:
    any of ($php*)
}

rule http_url_with_asp: medium {
  meta:
    description               = "contains hardcoded ASP endpoint"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"

  strings:
    $asp_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.asp/
    $asp_question = /[\.\w\-\_\/:]{0,160}\.asp\?[\w\-@\=]{0,32}/
    $asp_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.asp/

  condition:
    any of ($asp*)
}
