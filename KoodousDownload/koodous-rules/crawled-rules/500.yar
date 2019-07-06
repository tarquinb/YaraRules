
import "androguard"


rule hostingmy

{

    condition:

        androguard.certificate.issuer(/hostingmy0@gmail.com/)

}