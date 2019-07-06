
import "androguard"

import "file"

import "cuckoo"



rule WhatsAppGold

{

    meta:

        description = "Rule to detect WhatsApp Gold"

        sample = "26fe32f823c9981cb04b9898a781c5cdf7979d79b7fdccfb81a107a9dd1ef081"


    strings:

        $a = "mahmoodab99@gm"


    condition:

        all of ($a)

}