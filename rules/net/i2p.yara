rule i2p_user : suspicious {
  meta:
	description = "Uses the I2P Anonymous Network"
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2020_Prometei_B_uselvh323 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
    hash_2021_miner_andr_dzpsy = "64815d7c84c249e5f3b70d494791498ce85ea9a97c3edaee49ffa89809e20c6e"
    hash_2020_Prometei_lbjon = "75ea0d099494b0397697d5245ea6f2b5bf8f22bb3c3e6d6d81e736ac0dac9fbc"
    hash_2021_miner_TQ = "7955542df199c6ce4ca0bb3966dcf9cc71199c592fec38508dad58301a3298d0"
    hash_2021_miner_andr_aouid = "876b30a58a084752dbbb66cfcc003417e2be2b13fb5913612b0ca4c77837467e"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
  strings:
    $base32_i2p_domain = ".b32.i2p"
    $other_i2p_domain = /\.[a-z]{1,128}\.i2p/
    $i2p_relay = "/i2p."
    $i2p_projekt = "i2p_projekt"
    $i2p_router = "i2p.router"
  condition:
    any of them
}
