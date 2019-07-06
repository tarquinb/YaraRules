
rule Trojan_Banker_Slempo

{

    meta:

        description = "Trojan-Banker.Slempo"

        sample = "349baca0a31753fd8ad4122100410ee9"


    strings:

        $a = "org/slempo/service" nocase

        $b = /com.slempo.service/ nocase

        $c = "com/slempo/baseapp/Service" nocase

        $d = "org/slempo/baseapp/Service" nocase


    condition:

        1 of them


}