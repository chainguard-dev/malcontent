rule keychain_unlock: medium macos {
  meta:
    description = "Unlocks the Keychain"
    ref         = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"

  strings:
    $ref = "KeychainUnlock"

  condition:
    filesize < 100MB and any of them
}

rule keychain_unlock_high: high macos {
  meta:
    description = "Unlocks the Keychain"
    ref         = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"

  strings:
    $ref          = "KeychainUnlock"
    $not_remember = "Remember this password in my keychain"
    $not_fde      = "FileVaultMaster.keychain"
    $not_entitled = "com.apple.private.accounts.allaccounts"

  condition:
    filesize < 100MB and any of them and none of ($not*)
}
