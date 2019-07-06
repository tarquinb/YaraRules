
import "androguard"



rule smsSender

{

    meta:

        description = "Sends SMS. Final number is obfuscated, but easy to read. Code below."

        // Number10 is the final number.

    strings:

        $mfprice = "236"

        $price2 = "94.70"


    condition:

        androguard.package_name("com.software.application") and ($mfprice or $price2)


}