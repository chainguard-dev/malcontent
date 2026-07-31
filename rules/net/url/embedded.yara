rule malicious_https_url: critical {
  meta:
    description = "contains embedded, malicious HTTPS URLs"

  strings:
    $ = "https://mainnet.solana-rpc-pool.workers.dev"

  condition:
    any of them
}

rule https_url {
  meta:
    description = "contains embedded HTTPS URLs"

  strings:
    $ref       = /https:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $not_apple = "https://www.apple.com/appleca/"

  condition:
    // the Apple CA URL is itself a $ref match, so subtract its count instead of
    // switching the rule off: one known-good URL no longer excuses every other
    // URL in the file
    $ref and #ref > #not_apple
}

rule http_url {
  meta:
    description = "contains embedded HTTP URLs"

  strings:
    $ref = /http:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/

    // Match every apple.com URL, not one literal: signed macOS binaries carry
    // Apple CA/DTD boilerplate, so a single literal exclusion either excused
    // every other URL in the file (`none of`) or left the boilerplate itself
    // reported. Requiring a path after the host keeps a lookalike such as
    // apple.com.example.test from being excluded. Regex, not lookahead: yara-x
    // has no lookaround, so "non-Apple host" is expressed by counting.
    $not_apple = /http:\/\/[\w][\w\.\-]{0,32}apple\.com\/[\w\.\/\-_\?=\@]{0,64}/

  condition:
    // fire only on an http URL that no apple.com URL accounts for
    $ref and #ref > #not_apple
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
    description = "contains hardcoded PHP endpoint"

  strings:
    $php_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.php/
    $php_question = /[\.\w\-\_\/:]{0,160}\.php\?[\w\-@\=]{0,32}/
    $php_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.php/

  condition:
    any of ($php*)
}

rule http_url_with_asp: medium {
  meta:
    description = "contains hardcoded ASP endpoint"

  strings:
    $asp_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.asp/
    $asp_question = /[\.\w\-\_\/:]{0,160}\.asp\?[\w\-@\=]{0,32}/
    $asp_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.asp/

  condition:
    any of ($asp*)
}
