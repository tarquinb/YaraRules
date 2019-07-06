
import "androguard"

import "file"

import "cuckoo"



rule monero_miner3

{

    meta:

        description = "This rule detects samples with monero miner"

        sample = "530bd6c95c3a79c04f49880a44c348db"


    strings:

        $a_1 = "startMining"

        $a_2 = "stopMining"

        $a_3 = "moneroMiner"


    condition:

        all of ($a_*)

}