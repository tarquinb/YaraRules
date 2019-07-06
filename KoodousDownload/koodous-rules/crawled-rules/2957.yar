
import "androguard"



rule Generic : Suspicious Certs

{

    meta:

        description = "Generic Rule to identify APKs with suspicious certificates"


    condition:

        androguard.certificate.sha1("BD1C65A339E6D133C3C5ADB0A42205BE90F36CCD") 

            //Developer: "z" -> e.g. PinguLocker

        or androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") 

            //Developer: "Internet Widgits Pty Ltd" -> e.g. Marcher

        or androguard.certificate.sha1("10763B5D0F4DD9976815C1270072510E6A453798")

            //Developer: "Android" -> e.g. Slempo

        or androguard.certificate.sha1("FF3488E07D179A0E5EAD90E52D12F26E100B4CA6")

            //Developer: "Android" -> e.g. Slempo

        or androguard.certificate.sha1("140FC8781942E9DFF4C0E60CD3F8DDE6565A9D76")

            //Developer: "Android" -> e.g. Slempo

        or androguard.certificate.sha1("5AD2ACB089F8BE5112FF5125D94036983DE3E8D5")

            //Developer: "Unknown" -> e.g. Marcher / various "Flash Player" ...

        or androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")

            //Developer: "Londatiga" -> e.g. DroidJack / AndroRAT ...


}