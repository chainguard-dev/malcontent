import "dotnet"

rule RedLine_Campaign_June2021
{
    meta:
        id = "6obnDftS8HPC8ATVxov3ol"
        fingerprint = "4f389cf9f0343eb0e526c25f0beea9a0b284e96029dc064e85557ae2fe8bdf9d"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer's June 2021 campaign."
        category = "MALWARE"
        malware = "REDLINE"
        malware_type = "INFOSTEALER"
        reference = "https://bartblaze.blogspot.com/2021/06/digital-artists-targeted-in-redline.html"


    condition:
        dotnet.guids[0]=="a862cb90-79c7-41a9-847b-4ce4276feaeb" or dotnet.guids[0]=="a955bdf8-f5ac-4383-8f5d-a4111125a40e" or dotnet.guids[0]=="018ca516-2128-434a-b7c6-8f9a75dfc06e" or dotnet.guids[0]=="829c9056-6c93-42c2-a9c8-19822ccac0a4" or dotnet.guids[0]=="e1a702b0-dee1-463a-86d3-e6a9aa86348e" or dotnet.guids[0]=="6152d28b-1775-47e6-902f-8bdc9e2cb7ca" or dotnet.guids[0]=="111ab36c-09ad-4a3e-92b3-a01076ce68e0" or dotnet.guids[0]=="ea7dfb6d-f951-48e6-9e25-41c31080fd42" or dotnet.guids[0]=="34bca13d-abb5-49ce-8333-052ec690e01e" or dotnet.guids[0]=="1422b4dd-c4c1-4885-b204-200e83267597" or dotnet.guids[0]=="d0570d65-3998-4954-ab42-13b122f7dde5"
}