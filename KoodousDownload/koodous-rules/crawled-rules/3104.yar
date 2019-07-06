
import "androguard"


rule clicksummer

{

    meta:

        description = "domains used for copycat malware (CheckPoint)"


    strings:

        $ = ".clickmsummer.com"

        $ = ".mostatus.net"

        $ = ".mobisummer.com"

        $ = ".clickmsummer.com"

        $ = ".hummercenter.com"

        $ = ".tracksummer.com"


    condition:

        1 of them


}