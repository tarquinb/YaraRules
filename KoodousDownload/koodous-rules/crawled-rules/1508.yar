
import "androguard"

import "file"

import "cuckoo"



rule volcman_dropper

{

    meta:

        description = "Dropper"

        sample = "322dfa1768aac534989acba5834fae4133177fec2f1f789d9a369ebbf1f00219"

        certificate = "8AA6F363736B79F51FB7CF3ACFC75D80F051325F"


    condition:

        cuckoo.network.dns_lookup(/advolcman\.com/)

        or cuckoo.network.dns_lookup(/woltrezmhapplemouse\.com/)

        or cuckoo.network.dns_lookup(/aerovolcman\.com/)

}