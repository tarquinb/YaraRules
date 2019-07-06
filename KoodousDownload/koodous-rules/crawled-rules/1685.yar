
import "androguard"


rule xolosale

{

    strings:

        $ = "919211722715"

        $ = "servernumber"

        $ = "xolo"


    condition:

        ( androguard.url(/pu6b.vrewap.com:1337/i) or

        androguard.url(/pu6a.vrewap.com:1337/i) ) 

        or 

        all of them


}