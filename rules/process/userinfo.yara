
rule userinfo : medium {
  meta:
    syscall = "getuid"
    description = "returns user info for the current process"
    hash_1985_scripts_rsh = "ed706eb208f271abdbbe1cd7cd94cd8c8603f811018d5207a120c718f59652e9"
    hash_1985_scripts_rsh = "ed706eb208f271abdbbe1cd7cd94cd8c8603f811018d5207a120c718f59652e9"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
  strings:
    $ref = "os.userInfo()"
  condition:
    any of them
}
