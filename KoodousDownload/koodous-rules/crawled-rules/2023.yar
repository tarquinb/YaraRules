
import "androguard"


rule fake_framaroot

{

    meta:

        description = "This rule detects fake framaroot apks"

        sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"


    condition:

        androguard.app_name(/framaroot/i) and

        not androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816")


}