
import "androguard"


rule Click415to417

{

    strings:

     $ = "http://apk-archive.ru"

     $ = "aHR0cDovL2Fway1hcmNoaXZlLnJ1L2dvb2dsZXBsYXlhcHBzL2NoZWNrL281L2luZGV4LnBocD9pbXNpPQ"


    condition:

        androguard.url(/apk-archive.ru/i)

        or 

        1 of them


}