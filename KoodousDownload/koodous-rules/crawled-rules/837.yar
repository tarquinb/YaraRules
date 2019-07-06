
rule ghostpush

{

    meta:

        sample = "bf770e42b04ab02edbb57653e4e0c21b2c983593073ad717b82cfbdc0c7d535b"


    strings:

        $a = "assets/import.apkPK"

        $b = "assets/protect.apkPK"


    condition:

        all of them


}