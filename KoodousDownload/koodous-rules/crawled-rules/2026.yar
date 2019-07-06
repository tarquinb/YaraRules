
import "androguard"

import "file"

import "cuckoo"



rule test2

{

    meta:

        description = "This rule detects apps with VirusService"

        sample = "5C0A65D3AE9F45C9829FDF216C6E7A75AD33627A"


    condition:

        androguard.service(/\.VirusService/i)




}