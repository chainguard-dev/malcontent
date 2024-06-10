rule DotNet_Reactor
{
    meta:
        id = "1zLgWF57AJIATVZNMOyilu"
        fingerprint = "43687ec89c0f6dc52e93395ae5966e25bc1c2d2c7634936b6e9835773af19fa3"
        version = "1.1"
        date = "2024-03-20"
        modified = "2024-04-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies .NET Reactor, which offers .NET code protection such as obfuscation, encryption and so on."
        category = "INFO"
        reference_a = "https://www.eziriz.com/dotnet_reactor.htm"
        reference_b = "https://unprotect.it/technique/net-reactor/"

strings:
    $s1 = "{11111-22222-20001-00001}" ascii wide fullword
    $s2 = "{11111-22222-20001-00002}" ascii wide fullword
    $s3 = "{11111-22222-40001-00001}" ascii wide fullword
    $s4 = "{11111-22222-40001-00002}" ascii wide fullword
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.1.}
    $x1 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.2.}
    $x2 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.1.}
    $x3 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.2.}
    $x4 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}

condition:
    2 of ($s*) or 2 of ($x*)
}
