
rule smsspy

{

    meta:

        description = "This rule detects SMSSpy from Korea"

        sample = "ed1541efb7052dfe76e5e17338d68b291d68e9115e33e28b326dc4b63c7bfded"


    strings:

        $a = "getBodyParts"

        $b = "audioMode"

        $c = "InsertContacts"

        $d = "where cnt_phone="

        $e = "CallStateReceiver.java"

        $f = "CallBlock"

        $g = "set cnt_block="

        $h = "cnt_mail text"

        $i = "bSMSBlockState"

        $j = "cnt_phone text"

        $k = "getsmsblockstate.php?telnum="


    condition:

        all of them


}