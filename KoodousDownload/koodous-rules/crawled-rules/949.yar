
import "androguard"




rule koodous : official

{

    meta:

        description = "http://researchcenter.paloaltonetworks.com/2015/10/chinese-taomike-monetization-library-steals-sms-messages/"


    condition:

        androguard.url("http://112.126.69.51/2c.php")


}