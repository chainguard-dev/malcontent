
rule uname {
  meta:
    description = "system identification"
    pledge = "sysctl"
    syscall = "sysctl"
    ref = "https://man7.org/linux/man-pages/man1/uname.1.html"
  strings:
    $uname = "uname" fullword
    $uname2 = "syscall.Uname" fullword
  condition:
    any of them
}

rule os_release : medium {
  meta:
    description = "operating-system identification"
    pledge = "sysctl"
    syscall = "sysctl"
    ref = "https://developer.apple.com/documentation/os/1524245-os_release"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2023_RustBucket_Stage_3 = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
  strings:
    $ref = "os_release" fullword
  condition:
    any of them
}

rule macos_platform_check : medium {
  meta:
    description = "platform check"
    pledge = "sysctl"
    syscall = "sysctl"
    ref = "https://developer.apple.com/documentation/os/1524245-os_release"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
  strings:
    $ref = "isPlatformOrVariantPlatformVersionAtLeast" fullword
    $ref2 = "/System/Library/CoreServices/SystemVersion.plist" fullword
    $ref3 = "IOPlatformExpertDevice" fullword
  condition:
    any of them
}

rule python_platform : medium {
  meta:
    description = "system platform identification"
    ref = "https://docs.python.org/3/library/platform.html"
    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2024_aaa_bbb_ccc_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2023_setuptool_setuptool_setup = "50c9a683bc0aa2fbda3981bfdf0bbd4632094c801b224af60166376e479460ec"
  strings:
    $ref = "platform.dist()"
    $ref2 = "platform.platform()"
    $ref3 = "sys.platform"
  condition:
    any of them
}

rule npm_uname : medium {
  meta:
    description = "get system identification"
    ref = "https://nodejs.org/api/process.html"
    hash_2023_botbait = "1b92cb3d4b562d0eb05c3b2f998e334273ce9b491bc534d73bcd0b4952ce58d2"
    hash_2018_OSX_Dummy_script = "ced05b1f429ade707691b04f59d7929961661963311b768d438317f4d3d82953"
    hash_2024_2021_ua_parser_js_preinstall = "62e08e4967da57e037255d2e533b7c5d7d1f1773af2a06113470c29058b5fcd0"
  strings:
    $ref = "process.platform"
    $ref2 = "process.arch"
    $ref3 = "process.versions"
  condition:
    any of them
}
