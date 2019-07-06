
import "androguard"


rule lop_K

{

    meta:

        description = "This rule detects the lop files"

        sample = "f8537cc4bc06be5dd47cdee422c3128645d01a2536f6fd54d2d8243714b41bdd"


    strings:

        $a = "assets/daemon"

        $b = "assets/exp"


    condition:

        $a and $b

}