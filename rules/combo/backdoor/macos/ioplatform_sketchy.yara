rule ioplatform_expert_with_sketchy_calls {
  meta:
    hash_2020_Gravity_Spy_Enigma = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
    hash_2022_DazzleSpy_agent_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
    hash_2021_MacMa_qmfus = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2012_FileCoder = "c9c7c7f1afa1d0760f63d895b8c9d5ab49821b2e4fe596b0c5ae94c308009e89"
    hash_2022_Gimmick_CorelDRAW = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
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

