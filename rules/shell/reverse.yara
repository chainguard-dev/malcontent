rule reverse_shell : critical {
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

rule perl_reverse_shell : critical {
  meta:
    hash_2023_Linux_Malware_Samples_caa1 = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2018_OSX_Dummy_script = "ced05b1f429ade707691b04f59d7929961661963311b768d438317f4d3d82953"
    hash_2023_Win_Trojan_Perl_9aed = "9aed7ab8806a90aa9fac070fbf788466c6da3d87deba92a25ac4dd1d63ce4c44"
    hash_2023_uacert_socket = "912dc3aee7d5c397225f77e3ddbe3f0f4cf080de53ccdb09c537749148c1cc08"
  strings:
    $socket = "socket("
    $open = "open("
    $redir_double = "\">&"
    $redir_single = "'>&"

    $sh_i = "sh -i"
  condition:
    $socket and $open and any of ($redir*) and $sh_i
}
