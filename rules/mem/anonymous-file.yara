rule memfd_create: medium {
  meta:
    syscall     = "memfd_create"
    description = "create an anonymous file"
    capability  = "CAP_IPC_LOCK"

    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
    hash_2023_Pupy_2ab5             = "2ab59fa690e502a733aa1500a96d8e94ecb892ed9d59736cca16a09538ce7d77"

  strings:
    $ref = "memfd_create" fullword

  condition:
    any of them
}
