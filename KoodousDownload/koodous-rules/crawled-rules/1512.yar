
import "androguard"



rule FakeAngribirds

{

    meta:

        description = "This ruleset looks for angribirds not by rovio"



    condition:

        androguard.activity(/com.rovio.fusion/i) and not

        androguard.certificate.sha1("66DA9177253113474F6B3043B89E0667902CF115") 


}