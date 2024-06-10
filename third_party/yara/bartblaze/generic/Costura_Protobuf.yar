import "dotnet"
rule Costura_Protobuf
{
    meta:
        id = "2XP6PwlYvHaaVOgoVbFcQC"
        fingerprint = "da84b0a5628231b790fa802d404dcebd30c39805360e619ea78c6d56cf5d3c52"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Costura and Protobuf in .NET assemblies, respectively for storing resources and (de)serialization. Seen together might indicate a suspect binary."
        category = "INFO"
        reference_a = "https://github.com/Fody/Costura"
        reference_b = "https://github.com/protobuf-net/protobuf-net"
        reference_c = "https://any.run/cybersecurity-blog/pure-malware-family-analysis/"

strings:
    $comp = "costura.protobuf-net.dll.compressed" ascii wide fullword
    
condition:
    dotnet.is_dotnet and $comp
}
