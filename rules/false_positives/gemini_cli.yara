rule gemini_cli_third_party: override {
  meta:
    description                 = "gemini-cli bundled third-party npm dependencies"
    exotic_tld                  = "low"
    iplookup_website            = "low"
    browser_extension_installer = "low"
    obfuscated_payload          = "low"
    bash_persist                = "low"
    bash_persist_persistent     = "low"

  strings:
    $gemini_module = "@google/gemini-cli"
    $gemini_core   = "gemini-cli-core"

  condition:
    filesize < 100MB and all of them
}
