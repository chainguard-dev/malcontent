rule proc_self_mountinfo: medium {
  meta:
    description                   = "gets mount info associated to this process"
    pledge                        = "stdio"
    hash_2024_enumeration_deepce  = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
    hash_2024_BlackCat_45b8       = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"

  strings:
    $ref = "/proc/self/mountinfo"

  condition:
    $ref
}
