rule unusual_redir {
  meta:
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2021_trojan_Gafgyt_malxmr = "1b5bd0d4989c245af027f6bc0c331417f81a87fff757e19cdbdfe25340be01a6"
    hash_2018_trojan_TickerCoin_contir = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_gmera_licatrade = "49feb795e6d9bce63ee445e581c4cf4a8297fbf7848b6026538298d708bed172"
    hash_2023_Linux_Malware_Samples_aab5 = "aab526b32d703fd9273635393011a05c9c3f6204854367eb0eb80894bbcfdd42"
    hash_2023_Linux_Malware_Samples_da75 = "da7596a5308afddaa2197d62446761b9b437d423e57e7599a57d7ec65e342dce"
    hash_2023_Linux_Malware_Samples_eb67 = "eb67c56ec169940481e075a6b638d5f16e324aef6c2afcb8c4491b7ec1ed0058"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
  strings:
    $s_redir_stdin = " 0>&1"
    $s_redir_bash = "bash 2>/dev/null"
    $s_redir_bash_all = "bash &>"
    $s_redir_sh_i = "sh -i </tmp/p 2>&1"
    $s_sh_redir = "sh > /dev/null 2>&1"
    $s_bash_redir = "bash >/dev/null 2>&1"
    $s_tmp_and_null = />\/tmp\/[\.\w]{1,128} 2>\/dev\/null/
    $not_shell_if = "if ["
    $not_shell_local = "local -a"
  condition:
    any of ($s*) and none of ($not*)
}
