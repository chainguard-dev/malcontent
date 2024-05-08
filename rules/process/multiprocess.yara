
rule py_multiprocessing : notable {
  meta:
    syscall = "pthread_create"
    description = "uses python multiprocessing"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2023_Linux_Malware_Samples_03bb = "03bb1cfd9e45844701aabc549f530d56f162150494b629ca19d83c1c696710d7"
    hash_2023_Linux_Malware_Samples_05ca = "05ca0e0228930e9ec53fe0f0b796255f1e44ab409f91bc27d20d04ad34dcb69d"
  strings:
    $ref = "multiprocessing"
  condition:
    any of them
}
