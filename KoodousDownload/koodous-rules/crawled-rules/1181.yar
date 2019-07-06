
import "androguard"


rule marcher : official

{

    meta:

        description = "This rule detects the banker Marcher"

        sample = "d491e8ac326394e7b2cbc45c6599a677b6601978af87bc39c6bb0c41ba24f24e"


    strings:

        $cromosome_a = "setUsesChronometer"

        $cromosome_b = "Card number"

        $cromosome_c = "USSDService"

        $cromosome_d = "getDirtyBounds"

        $cromosome_e = "account_number_edit"


    condition:

        all of ($cromosome_*)


}