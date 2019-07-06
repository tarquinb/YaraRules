
import "androguard"




rule subscript

{

    meta:

        description = "Coonecting to one of those sites (Splitting ',') and getting the user into a subscription."



    strings:

        $a = "fapecalijobutaka.biz,ymokymakyfe.biz,kugoheba.biz"


    condition:

        $a 


}