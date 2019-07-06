
import "androguard"


rule Ransom {

    meta: 

        description = "ransomwares" 

    strings:

        $a = "!2,.B99^GGD&R-"

        $b = "22922222222222222222Q^SAAWA"


    condition:

        $a or $b

}


rule fakeInstalls {

    meta:

     description = "creates fake apps (usually low sized) for malicious purposes."


    condition:

        androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")

}