
import "androguard"

import "file"

import "cuckoo"



rule test_obfuscated_marcher

{

    meta:

        description = "This rule detects the koodous application, used to show all Yara rules potential"

        sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"


    strings:

        $b_1 = "vi?rus"

        $b_2 = "a?v?g"

        $b_3 = "a?nt?i"

        $b_4 = "v?i?ru?s"


    condition:

        any of ($b_*)



}