
rule packers : qihoo

{

    meta:

        description = "This rule detects packers based on files used by them"

        description2 = "This is for an old version, new versions use 360 and qihoo activities"



    strings:

        $qihoo_1 = "monster.dex"

        $qihoo_2 = "libprotectClass"


    condition:

        2 of them


}