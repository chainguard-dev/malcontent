rule openpanel_fontkitten_brotli: override {
  meta:
    description = "fontkitten Brotli static dictionary for WOFF2 decompression"
    xor_url     = "low"
    xor_certs   = "low"
    xor_terms   = "low"

  strings:
    $unpack      = /unpackDictionaryData/
    $cff_top     = /CFFTop/
    $restructure = /@fontkitten\/restructure/

  condition:
    filesize < 1MB and $unpack and any of ($cff_top, $restructure)
}

rule openpanel_rrweb_replay: override {
  meta:
    description         = "rrweb replay and rrweb-player UMD bundles with an inline base64 worker"
    base64_shell_base64 = "low"

  strings:
    $rebuilt      = /FullsnapshotRebuilded/
    $original_src = /rrweb-original-src/

  condition:
    filesize < 500KB and all of them
}

rule openpanel_lighthouse: override {
  meta:
    description                  = "Lighthouse DevTools bundle in @react-native/debugger-frontend"
    exotic_tld                   = "low"
    geoip_website_value          = "low"
    iplookup_website             = "low"
    unsigned_bitwise_math_excess = "low"
    js_eval_obfuscated_fromChar  = "low"

  strings:
    $lh_warning = /LighthouseRunWarning/
    $lh_bundle  = /lighthouse-dt-bundle/
    $lh_version = /lighthouseVersion/
    $lh_marker  = /lighthouseMarker/

  condition:
    filesize < 4MB and 2 of them
}

rule openpanel_api_dist: override {
  meta:
    description                = "openpanel-api apps/api/dist/index.js with notification integrations"
    http_hardcoded_ip          = "medium"
    discord_bot                = "medium"
    discord_password_post_chat = "medium"
    obfuscated_payload         = "low"
    geoip_website_value        = "medium"

  strings:
    $analytics = /getAnalyticsOverviewCore/
    $cookie    = /parseCookieDomain/

  condition:
    filesize < 16MB and all of them
}
