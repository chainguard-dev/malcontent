private rule Macho {
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}

rule MACOS_LIGHTSPY_LOADER_20240422 {
    meta:
        description = "Detects on the LightSpy loader"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
        hash2 = "77e983dcde7752278c0fbfc29d92b237c3961de7517d7bcf0877ce83e9b58278"

    strings:
        $a0 = "FrameworkLoader"
        $a1 = "PLATFORM_MACOS"
        $a2 = { 44 6f 77 6e 6c 6f 61 64 65 72 }


    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_IMPLANT_20240422 {
    meta:
        description = "Detects on the LightSpy implant"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

    strings:
        $a0 = { 52 65 61 6c 54 69 6d 65 43 6d 64 }
        $a1 = { 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 74 5f 63 6f 6e 66 69 67 }
        $a2 = { 2f 76 61 72 2f 63 6f 6e 74 61 69 6e 65 72 73 2f 42 75 6e 64 6c 65 2f 69 72 63 62 69 6e 2e 70 6c 69 73 74 }
        $a3 = { 74 5f 63 6f 6d 6d 61 6e 64 5f 70 6c 61 6e }
        $a4 = { 63 6f 6d 2e 61 6c 61 6d 6f 66 69 72 65 2e }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_AUDIODYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libAudioRecorder dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "0f662991dbd0568fc073b592f46e60b081eedf0c18313f2c3789e8e3f7cb8144"

    strings:
        $path = "/usr/local/lib/libAudioRecorder.dylib"

        $a0 = { 61 72 63 6c 69 74 65 }
        $a1 = { 41 75 64 69 6f 52 65 63 6f 72 64 65 72 }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_BROWSERHISTORYDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libBrowserHistory dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "3d6ef4d88d3d132b1e479cf211c9f8422997bfcaa72e55e9cc5d985fd2939e6d"

    strings:
        $path = "/usr/local/lib/libBrowserHistory.dylib"

        $a0 = "/Library/Application Support/Google/Chrome/Default/History"
        $a1 = "/Library/Safari/History.db"
        $a2 = { 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 }
        $a3 = { 61 72 63 6c 69 74 65 }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_CAMERADYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libCameraShot dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "18bad57109ac9be968280ea27ae3112858e8bc18c3aec02565f4c199a7295f3a"

    strings:
        $path = "/usr/local/lib/libCameraShot.dylib"

        $a0 = { 61 72 63 6c 69 74 65 }
        $a1 = { 43 61 6d 65 72 61 53 68 6f 74 }
        $a2 = { 54 61 6b 65 50 69 63 74 75 72 65 2e (6d | 68) }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_FILEMANAGEDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libFileManage dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "5fb67d42575151dd2a04d7dda7bd9331651c270d0f4426acd422b26a711156b5"

    strings:
        $path = "/usr/local/lib/libFileManage.dylib"

        $a0 = "GetTelegramFileDir" 
        $a1 = { 46 69 6c 65 4d 61 6e 61 67 65 20 44 6f 77 6e 4c 6f 61 64 46 69 6c 65 }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_KEYCHAINDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libKeyChains dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "65aa91d8ae68e64607652cad89dab3273cf5cd3551c2c1fda2a7b90aed2b3883"

    strings:
        $path = "/usr/local/lib/libKeyChains.dylib"

        $a0 = { 6d 61 63 20 4b 65 79 20 43 68 61 69 6e 73 }
        $a1 = { 2f 61 70 69 2f 6b 65 79 63 68 61 69 6e }
        $a2 = { 6b 53 65 63 41 74 74 72 49 73 73 75 65 72 }
        $a3 = "PLATFORM_MACOS"

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_LANDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libLanDevices dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "4511567b33915a4c8972ef16e5d7de89de5c6dffe18231528a1d93bfc9acc59f"

    strings:
        $path = "/usr/local/lib/libLanDevices.dylib"

        $a0 = "CoreWLAN.framework"
        $a1 = { 2f 61 70 69 2f 6c 61 6e 5f 64 65 76 69 63 65 73 }
        $a2 = { 4d 61 63 46 69 6e 64 65 72 }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_PROCESSANDAPPDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libProcessAndApp dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "d2ccbf41552299b24f186f905c846fb20b9f76ed94773677703f75189b838f63"

    strings:
        $path = "/usr/local/lib/libProcessAndApp.dylib"

        $a0 = { 50 72 6f 67 72 65 73 73 4c 6f 67 2e 6d }
        $a1 = { 2f 61 70 69 2f (61 70 70 2f | 70 72 6f 63 65 73 73 2f) }
    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_SCREENRECORDERDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libScreenRecorder dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "7ed786a259982cce0fad8a704547c72690970145b9587d84ee6205b7c578b663"

    strings:
        $path = "/usr/local/lib/libScreenRecorder.dylib"

        $a0 = { 2f 78 38 36 5f 36 34 2f 53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 2e 6f }
        $a1 = { 00 72 65 63 6f 72 64 20 73 63 72 65 65 6e }

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_SHELLDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libShellCommand dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "ac6d34f09fcac49c203e860da00bbbe97290d5466295ab0650265be242d692a6"

    strings:
        $path = "/usr/local/lib/libShellCommand.dylib"

        $a0 = { 2f 61 70 69 2f 73 68 65 6c 6c 2f 72 65 73 75 6c 74 }
        $a1 = "XXXExeCommand"
        $a2 = "GetDeviceID"

    condition:
        Macho and all of them
}

rule MACOS_LIGHTSPY_WIFIDYLIB_20240422 {
    meta:
        description = "Detects on the LightSpy libWifiList dylib"
        author = "Stuart Ashenbrenner, Alden Schmidt"
        date = "2024-04-22"
        modified = "2024-04-22"

        reference = "https://huntress.com/blog/lightspy-malware-variant-targeting-macos"
        hash1 = "fc7e77a56772d5ff644da143718ee7dbaf7a1da37cceb446580cd5efb96a9835"

    strings:
        $path = "/usr/local/lib/libWifiList.dylib"

        $a0 = { 2f 61 70 69 2f 77 69 66 69 5f (63 6f 6e 6e 65 63 74 69 6f 6e 2f | 6e 65 61 72 62 79 2f) }
        $a1 = { 57 50 41 [1] 2d 50 53 4b }

    condition:
        Macho and all of them
}
