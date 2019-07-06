
import "androguard"



rule feckeny

{

    meta:

        description = "This ruleset looks for feckeny's apps"


    condition:

        androguard.certificate.issuer(/feckeny/) 

        or androguard.certificate.subject(/feckeny/)

}