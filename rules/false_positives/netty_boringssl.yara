rule netty_boringssl_dll: override {
  meta:
    description               = "Netty native BoringSSL Windows DLLs (tcnative, quiche)"
    CAPE_Nitrogenloaderconfig = "harmless"

  strings:
    $jni_tcnative = "JNI_OnLoad_netty_tcnative"
    $jni_quiche   = "JNI_OnLoad_netty_quiche"
    $boringssl    = "boringssl"

  condition:
    filesize < 10MB and $boringssl and ($jni_tcnative or $jni_quiche)
}
