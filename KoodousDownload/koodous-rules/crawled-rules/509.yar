
import "androguard"


rule leadbolt : advertising

{

    meta:

        description = "Leadbolt"


    condition:

        androguard.url(/http:\/\/ad.leadbolt.net/)

}