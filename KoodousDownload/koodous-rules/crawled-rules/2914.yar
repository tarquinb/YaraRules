
import "androguard"


rule certs

{


    condition:

        androguard.certificate.sha1("3F65615D7151BA782F9C0938B01F4834B8E492BC") or

        androguard.certificate.sha1("AFD2E81E03F509B7898BFC3C2C496C6B98715C58") or

        androguard.certificate.sha1("E6D2E5D8CCBB5550E666756C804CA7F19A523523") or

        androguard.certificate.sha1("7C9331A5FE26D7B2B74C4FB1ECDAF570EFBD163C")          // Ransomware Locker



}