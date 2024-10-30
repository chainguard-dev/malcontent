rule rc4_ksa: harmless {
  meta:
    author      = "Thomas Barabosch"
    description = "potential RC4 key scheduling algorithm"

  strings:
    $cmp_eax_256 = { 3d 00 01 00 00 }  // cmp eax, 256
    $cmp_e_x_256 = { 81 f? 00 01 00 00 }  // cmp {ebx, ecx, edx}, 256
    $cmp_rax_256 = { 48 3d 00 01 00 00 }  // cmp rax, 256
    $cmp_r_x_256 = { 48 81 f? 00 01 00 00 }  // cmp {rbx, rcx, …}, 256

  condition:
    any of them
}
