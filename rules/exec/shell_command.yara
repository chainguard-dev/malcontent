rule system : medium {
  meta:
    description = "execute a shell command"
    syscalls = "fork,execl"
    ref = "https://man7.org/linux/man-pages/man3/system.3.html"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_123e = "123e6d1138bfd58de1173818d82b504ef928d5a3be7756dd627c594de4aad096"
    hash_2023_Linux_Malware_Samples_2bc8 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
  strings:
    $system = "system" fullword
  condition:
    all of them in (1200..3000)
}

rule php_shell_exec : high {
  meta:
    description = "execute a shell command"
    syscalls = "fork,execl"
  strings:
    $ref = /shell_exec[\(\$\w\)]{0,16}/
  condition:
	$ref
}
