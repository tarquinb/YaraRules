
import "androguard"



rule banker_string : banker string

{

    meta:

        description = "This family detect your region for subscribe to MMS premium msg. Use ThoughtCrime for WhisperSystems"

        sample = "ea3999c8c9ff732c8df7a261b3b1e0e33510fd9c2ea1e355660224ed8497d8e4"


    strings:

        $string_a = "SmsSecure erkannt"

        $string_b = "ITEM_VIEW_TYPE_FOOTER"

        $string_c = "555&&&555&&&"

        $string_d = "EFIl database di default non verr"

        $string_e = "99registration_activity__your_country_code_and_phone_number"

        $string_f = "Saving attachment to SD card..."

        $string_g = "NUMERO DI TELEFONO"


    condition:

        all of ($string_*)      

}


rule banker_certificate : banker certificate

{

    meta:

        description = "This rule detects banker"

        sample = "ea3999c8c9ff732c8df7a261b3b1e0e33510fd9c2ea1e355660224ed8497d8e4"


    condition:

        androguard.certificate.sha1("A7A3310E1335089F985E331523E1DAAB3F319A44") or

        androguard.certificate.sha1("33188A4658EA53F092DC6F9025CFD739E762CBEA") or

        androguard.certificate.sha1("06220B02289A3B44A969E8E5F23F7598D2CE563C") or

        androguard.certificate.sha1("27051D4C951095B6DC3BA59C1F21B9BCEEC02CEF")

}