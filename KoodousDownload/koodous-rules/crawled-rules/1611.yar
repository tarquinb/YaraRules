
import "cuckoo"


rule mopub : adware

{

    meta:

        description = "This rule detects apks thats connects to http://www.mopub.com/ adware company - not reference for malware"

        sample = "273ea61d4aea7cd77e5c5910ce3627529428d84c802d30b8f9d6c8d227b324c1"


    condition:

        cuckoo.network.dns_lookup(/ads\.mopub\.com/)


}