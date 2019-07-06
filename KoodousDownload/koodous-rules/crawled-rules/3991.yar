
import "androguard"

import "file"

import "cuckoo"



rule monero_miner2

{

    meta:

        description = "This rule detects samples with monero miner"

        sample = "709a703e193e6b1130307ecdbb394ca2"



    condition:

        androguard.service(/CoinHiveIntentService/) and

        androguard.certificate.sha1("A94017A56275BBAC8C31166CCE314A49C029E959")

}