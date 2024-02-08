rule contains_base64 : Base64
{
    meta:
        author = "Jaume Martin"
        description = "This rule finds for base64 strings"
        version = "0.2"
        notes = "https://github.com/Yara-Rules/rules/issues/153"
    strings:
        $a = /([A-Za-z0-9+\/]{4}){64,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
    condition:
        $a
}