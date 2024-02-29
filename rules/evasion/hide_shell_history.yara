rule hide_shell_history : suspicious {
  meta:
	description = "Hides shell command history"
    hash_2022_trojan_Winnti = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2022_XorDDoS_0Xorddos = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2023_articles_https_www_intezer_com_blog_malware_analysis_hiddenwasp_malware_targeting_linux_systems = "4558b35302720a58cf80271cf1a87da93dcb55113d4e9ccd8c211e9fd9febbef"
    hash_2023_BPFDoor_93f4 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
    hash_2023_FontOnLake_BFCC4E6628B63C92BC46219937EA7582EA6FBB41_elf = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee"
    hash_2023_UPX_204046B3279B487863738DDB17CBB6718AF2A83A_elf_x86_64 = "6187541be6d2a9d23edaa3b02c50aea644c1ac1a80ff3e4ddd441b0339e0dd1b"
    hash_2023_OK_9c77 = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"
  strings:
    $hide_this = "HIDE_THIS"
    $histfile = "HISTFILE=" fullword
    $histfile_dev = "HISTFILE=/dev"
    $histcontrol = /HISTCONTROL=\"*ignorespace/
    $h_shopt_history = "shopt -ou history"
    $h_set_o_history = "set +o history"
    $histsize_0 = "HISTSIZE=0"
    $h_gotcha = "GOTCHA"
	$not_increment = "HISTSIZE++"
  condition:
    any of ($h*) and none of ($not*)
}
