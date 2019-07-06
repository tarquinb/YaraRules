
import "androguard"



rule AoHaHa: SMSSender

{

    condition:

        androguard.certificate.sha1("79A25BCBF6FC9A452292105F0B72207C3381F288")

}