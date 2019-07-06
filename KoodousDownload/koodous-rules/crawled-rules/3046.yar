
rule antiemulator

{

    meta:

        description = "Detect dumb antiemulator techniques"



    strings:

        $a = "google_sdk"

        $b = "generic"

        $c = "goldfish"


    condition:

        all of them


}