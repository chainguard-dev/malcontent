rule gemini_cli_third_party: override {
  meta:
    description                 = "gemini-cli bundled third-party npm dependencies"
    exotic_tld                  = "low"
    iplookup_website            = "low"
    geoip_website_value         = "low"
    browser_extension_installer = "low"
    obfuscated_payload          = "low"
    load_agent_with_payload     = "low"
    bash_persist                = "low"
    bash_persist_persistent     = "low"

  strings:
    $lighthouse = "lighthouse-devtools-mcp-bundle.js"
    $entities   = "entities-nostats.json"

  condition:
    filesize < 100MB and all of them
}
