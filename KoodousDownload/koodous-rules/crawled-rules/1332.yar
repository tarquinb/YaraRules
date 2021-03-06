
rule tachi

{

    meta:

        description = "This rule detects tachi apps (not all malware)"

        sample = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"


    strings:

        $a = "svcdownload"

        $xml_1 = "<config>"

        $xml_2 = "<apptitle>"

        $xml_3 = "<txinicio>"

        $xml_4 = "<txiniciotitulo>"

        $xml_5 = "<txnored>"

        $xml_6 = "<txnoredtitulo>"

        $xml_7 = "<txnoredretry>"

        $xml_8 = "<txnoredsalir>"

        $xml_9 = "<laurl>"

        $xml_10 = "<txquieresalir>"

        $xml_11 = "<txquieresalirtitulo>"

        $xml_11 = "<txquieresalirsi>"

        $xml_12 = "<txquieresalirno>"

        $xml_13 = "<txfiltro>"

        $xml_14 = "<txfiltrourl>"

        $xml_15 = "<posicion>"



    condition:

        $a and 4 of ($xml_*)

}