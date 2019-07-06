
rule packers : ali

{

    meta:

        description = "This rule detects packers based on files used by them"



    strings:


        $ali_1 = "libmobisecy.so"

        $ali_2 = "libmobisecy1.zip"


    condition:

        any of them


}