
import "androguard"


rule FakeWhatsApp

{

    meta:

        description = "Fake WhatsApp applications"


    condition:

        androguard.app_name("WhatsApp") and

        not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")

}