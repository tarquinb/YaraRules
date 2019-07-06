
import "androguard"


rule FakeFacebook

{

    meta:

        description = "Fake Facebook applications"


    condition:

        androguard.app_name("Facebook") and

        not androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9") 

}