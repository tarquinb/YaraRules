
rule nang

{

    meta:

        description = "Little and simple SMSFraud"

        sample = "8f1ee5c8e529ed721c9a8e0d5546be48c2bbc0c8c50a84fbd1b7a96831892551"


    strings:

        $a = "NANG"

        $b = "deliveredPI"

        $c = "totalsms.txt"


    condition:

        all of them


}