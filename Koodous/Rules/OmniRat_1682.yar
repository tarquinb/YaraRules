import "androguard"

rule OmniRat: Certs
{
    condition:
        androguard.certificate.sha1("B17BACFB294A2ADDC976FE5B8290AC27F31EB540")
        
}