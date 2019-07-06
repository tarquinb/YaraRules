
rule Trojan_Banker:Marcher {


    strings:

        $ = "Landroid/telephony/SmsManager"

        $ = "szClassname"

        $ = "szICCONSEND"

        $ = "szModuleSmsStatus"

        $ = "szModuleSmsStatusId"

        $ = "szName"

        $ = "szNomer"

        $ = "szNum"

        $ = "szOk"

        $ = "szTel"

        $ = "szText"

        $ = "szpkgname"


    condition:

        all of them

}