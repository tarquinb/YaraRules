
rule packers : liapp

{

    meta:

        description = "This rule detects packers based on files used by them"



    strings:

        $liapp_1 = "LIAPPEgg.dex"

        $liapp_2 = "LIAPPEgg"


    condition:

        2 of them


}