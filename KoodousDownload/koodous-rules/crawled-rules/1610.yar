
import "androguard"

import "cuckoo"


rule parse

{

    meta:

        description = "This rule detects aplicactions relationship with http://parse.com/"

        sample = ""


    condition:

        cuckoo.network.dns_lookup(/api\.parse\.com/)


}