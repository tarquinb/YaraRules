
import "androguard"

import "file"

import "cuckoo"



rule plantsvszombies:SMSFraud

{

    meta:

        sample = "ebc32e29ceb1aba957e2ad09a190de152b8b6e0f9a3ecb7394b3119c81deb4f3"



    condition:

        androguard.certificate.sha1("2846AFB58C14754206E357994801C41A19B27759")



}