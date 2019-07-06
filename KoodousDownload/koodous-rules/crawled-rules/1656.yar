
rule clicksummer

{

    meta:

        description = "test clicksummer"


    strings:

        $a = "statsevent.clickmsummer.com:80/log"

        $b = "54.149.205.221:8080/MobiLog/log"


    condition:

        1 of them


}



rule SMS1

{

    meta:

        description = "test com.pigeon.pimento.pimple"


    strings:

        $a = "SHA1-Digest: Itv2yusaL6KWWE/TLZFej7FVCO0="


    condition:

        1 of them


}