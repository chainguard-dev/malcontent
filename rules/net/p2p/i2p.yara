
rule i2p_user : high {
  meta:
    description = "Uses the I2P Anonymous Network"
    hash_2023_Linux_Malware_Samples_2bc8 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
    hash_2023_Linux_Malware_Samples_6481 = "64815d7c84c249e5f3b70d494791498ce85ea9a97c3edaee49ffa89809e20c6e"
    hash_2023_Linux_Malware_Samples_75ea = "75ea0d099494b0397697d5245ea6f2b5bf8f22bb3c3e6d6d81e736ac0dac9fbc"
  strings:
    $base32_i2p_domain = ".b32.i2p"
    $other_i2p_domain = /\.[a-z]{1,128}\.i2p/
    $i2p_relay = "/i2p."
    $i2p_projekt = "i2p_projekt"
    $i2p_router = "i2p.router"
  condition:
    any of them
}
