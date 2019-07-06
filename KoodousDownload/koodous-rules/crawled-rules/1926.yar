
import "androguard"


rule Twittre

{

    condition:

        androguard.certificate.sha1("CEEF7C87AA109CB678FBAE9CB22509BD7663CB6E") and not

        androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA") //original



}