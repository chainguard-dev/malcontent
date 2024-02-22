
rule reverse_shell : suspicious {
  meta:
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2023_pack_pack_cc6fbeece99f392c9c2228fcc6babc5dd09ab31b = "d6e781df92a93bc867b53c8310d6b04ceed9df64bd28b2e6e6264fa4fc44e1aa"
    hash_2023_Linux_Malware_Samples_d744 = "d7444cf0e30f3fc35cf13fa3726041bf0fbf80b289a88632fdae062a41094fb8"
  strings:
    $bash_dev_tcp = "bash -i >& /dev/tcp/"
    $stdin_redir = "0>&1" fullword
    $reverse_shell = "reverse_shell"
    $reverse_space_shell = "reverse shell" nocase
    $revshell = "revshell"
  condition:
    any of them
}
