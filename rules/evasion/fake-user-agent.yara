
rule fake_user_agent : suspicious {
  meta:
    hash_2018_A_Updater = "5e54bccbd4d93447e79cda0558b0b308a186c2be571c739e5460a3cb6ef665c0"
    hash_2019_trojan_NukeSped_Lazarus_AppleJeus = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
    hash_2020_Base_lproj_SubMenu = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
    hash_2020_Dacls_SubMenu = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
    hash_2020_Prometei_B_uselvh323 = "2bc8694c3eba1c5f066495431bb3c9e4ad0529f53ae7df0d66e6ad97a1df4080"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2021_CoinMiner_Sysrv = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2021_trojan_Gafgyt_23DZ = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2021_miner_KB_Elvuz = "0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6"
    hash_2021_Merlin_ispoh = "683e1eb35561da89db96c94f400daf41390bd350698c739c38024a1f621653b3"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Mirai_aspze = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_trojan_Mirai_leeyo = "ff2a39baf61e34f14f9c49c27faed07bdd431605b3c845ab82023c39589e6798"
    hash_2021_trojan_Gafgyt_U = "3eb78b49994cf3a546f15a7fbeaf7e8b882ebd223bce149ed70c96aab803521a"
    hash_2021_trojan_Gafgyt_U = "f7de003967a15ebf61e53e75c4d7b7ebf3455dc9609fe91140be1049019d02b9"
    hash_2021_trojan_Mirai_gsjmm = "dcd318efe5627e07a8eda9104ede1f510e43f5c0ae7f74d411137e1174f2844b"
    hash_2022_XorDDoS_0Xorddos = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2023_cobaltstrike_beacon = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2023_NukeSped_Lazarus_Internal_PDF_Viewer = "e74e8cdf887ae2de25590c55cb52dad66f0135ad4a1df224155f772554ea970c"
    hash_2023_RustBucket_Stage_3 = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
    hash_2023_trojan_Gafgyt_Mirai_gnhow = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
  strings:
    $u_msie = "compatible; MSIE"
    $u_khtml = /KHTML, like Gecko\w Version\/\d+.\d+ Safari/
    $u_gecko = "Gecko/20"
    $u_chrome = "(KHTML, like Gecko) Chrome"
    $u_chrome_other = /Google Chrome\/\d+\.\d/
    $u_wordpress = "User-Agent: Internal Wordpress RPC connection"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_electron = "ELECTRON_RUN_AS_NODE"
  condition:
    any of ($u_*) and none of ($not_*)
}