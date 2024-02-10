rule contains_base64 : suspicious
{
    meta:
        author = "Jaume Martin"
        description = "Contains base64 content"
    strings:
        $a = /([A-Za-z0-9+\/]{4}){32,4096}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
    condition:
        $a
}