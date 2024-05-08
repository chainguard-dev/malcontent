
rule exotic_pid_file : high {
  meta:
    description = "unusual pid (process id) file location"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_UPX_0a07c056fec72668d3f05863f103987cc1aaec92e72148bf16db6cfd58308617_elf_x86_64 = "94f4de1bd8c85b8f820bab936ec16cdb7f7bc19fa60d46ea8106cada4acc79a2"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
  strings:
    $users = /\/Users\/[%\w\.\-\/]{0,64}\.pid/
    $tmp = /\/tmp\/[%\w\.\-\/]{0,64}\.pid/
    $hidden = /[\w\/]{0,32}\/\.[\%\w\.\-\/]{0.16}\.pid/
  condition:
    any of them
}
