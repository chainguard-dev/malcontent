// Anchored on build identifiers rather than the keychain lookup itself, which a
// stealer targeting Anthropic API keys would also carry. Each override rule
// applies a single severity to all of its keys, hence two rules.
rule claude_code_capabilities: override {
  meta:
    description            = "Claude Code native CLI binary"
    find_generic_password  = "medium"
    zsh_history            = "medium"
    hostinfo_collector_api = "medium"

  strings:
    $package    = /@anthropic-ai\/claude-code/
    $entrypoint = /CLAUDE_CODE_ENTRYPOINT/
    $bedrock    = /CLAUDE_CODE_USE_BEDROCK/

  condition:
    filesize > 100MB and filesize < 400MB and #package > 20 and $entrypoint and $bedrock
}

rule claude_code_coincidental: override {
  meta:
    description                  = "Claude Code native CLI binary"
    multiple_browser_credentials = "low"
    ssh_backdoor                 = "low"
    suspected_data_stealer       = "low"

  strings:
    $package    = /@anthropic-ai\/claude-code/
    $entrypoint = /CLAUDE_CODE_ENTRYPOINT/
    $bedrock    = /CLAUDE_CODE_USE_BEDROCK/

  condition:
    filesize > 100MB and filesize < 400MB and #package > 20 and $entrypoint and $bedrock
}
