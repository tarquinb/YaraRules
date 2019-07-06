
import "androguard"


rule PUA: Untrusted_Cert

{

    condition:

        androguard.certificate.sha1("7E1119BBD05DE6D0CBCFDC298CD282984D4D5CE6") or

        androguard.certificate.sha1("DEF68058274368D8F3487B2028E4A526E70E459E")

}


rule Suspect

{

    strings: 

        $ = "tppy.ynrlzy.cn"


    condition:

        1 of them

}