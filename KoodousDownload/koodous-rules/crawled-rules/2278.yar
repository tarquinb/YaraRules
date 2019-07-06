
import "androguard"



rule Banker

{

    condition:

        androguard.certificate.issuer(/@attentiontrust\.[a-z]{2,3}/) and

        androguard.certificate.issuer(/Attention Trust/)


}