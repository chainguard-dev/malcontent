
rule ioplatform_expert_with_sketchy_calls {
  strings:
    $ioplatform = "IOPlatformExpertDevice" fullword
    $o_ioreg = "ioreg -"
    $o_your_docs = "your documents"
    $o_form = "application/x-www-form-urlencoded"
    $o_payment = "paymentAccepted"
    $o_file_recovery = "FileRecovery"
    $o_recover_files = "RecoverFiles"
    $o_keysteal = "keysteal"
    $o_keychain_items = "Keychain items"
    $o_killall_9 = "killall -9"
    $o_kill_9 = "kill -9"
    $o_call_history = "CallHistoryTransactions"
    $o_grepr = "grep -r \"%@\" %@"
    $o_ps = "ps -eo comm,pid"
    $o_ifconfig = "ifconfig"
    $o_launch = "rm -rf"
    $o_decrypting = "Decrypting"
    $o_encrypting = "Encrypting"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_crashpad = "crashpad_info"
    $not_osquery = "OSQUERY_WORKER"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_chromium = "RasterCHROMIUM"
    $not_c1_msal = "MSALAuthScheme"
    $not_license = "LicensePrice"
    $not_licensed = "licensed"
    $not_arc = "WelcomeToArc"
  condition:
    (filesize < 157286400 and $ioplatform and 3 of ($o_*)) and none of ($not*)
}
