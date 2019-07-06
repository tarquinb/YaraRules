
import "androguard"



rule SMSFraud

{



    condition:


        androguard.certificate.issuer(/\/C=UK\/ST=Portland\/L=Portland\/O=Whiskey co\/OU=Whiskey co\/CN=John Walker/)


}