
rule dl_user : suspicious {
  meta:
    description = "dynamically executes code bundles"
    ref = "https://developer.apple.com/documentation/foundation/bundle"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
    hash_2018_MacOS_Installer = "939cd1780d360792e6df92f415627c4c099bead6a97426a9f49ab179f5e4c47d"
  strings:
    $nsbundle = "NSBundle" fullword
    $close = "dlclose" fullword
    $error = "dlerror" fullword
    $open = "dlopen" fullword
    $sym = "dlsym" fullword
  condition:
    all of them
}
