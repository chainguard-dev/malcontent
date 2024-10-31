rule ioplatform_expert_with_sketchy_calls: high {
  meta:
    hash_2022_DazzleSpy_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
    hash_2017_FileCoder                = "c9c7c7f1afa1d0760f63d895b8c9d5ab49821b2e4fe596b0c5ae94c308009e89"

  strings:
    $ioplatform       = "IOPlatformExpertDevice" fullword
    $o_ioreg          = "ioreg -"
    $o_your_docs      = "your documents"
    $o_form           = "application/x-www-form-urlencoded"
    $o_payment        = "paymentAccepted"
    $o_file_recovery  = "FileRecovery"
    $o_recover_files  = "RecoverFiles"
    $o_keysteal       = "keysteal"
    $o_keychain_items = "Keychain items"
    $o_killall_9      = "killall -9"
    $o_kill_9         = "kill -9"
    $o_call_history   = "CallHistoryTransactions"
    $o_grepr          = "grep -r \"%@\" %@"
    $o_ps             = "ps -eo comm,pid"
    $o_ifconfig       = "ifconfig"
    $o_launch         = "rm -rf"
    $o_decrypting     = "Decrypting"
    $o_encrypting     = "Encrypting"

  condition:
    filesize < 104857600 and $ioplatform and 4 of ($o_*)
}
