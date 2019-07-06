
import "androguard"

import "file"

import "cuckoo"



rule miner_suspicious

{

    meta:

        description = "This rule detects the koodous application, used to show all Yara rules potential"

        sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"


    strings:

        $a_1 = "miner.start()"

        $b_2 = "libcpuminer.so"

        $b_3 = "libcpuminerpie.so"


    condition:

        $a_1 or any of ($b_*)



}