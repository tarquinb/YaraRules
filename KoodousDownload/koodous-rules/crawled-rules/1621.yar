
import "androguard"


rule VideoTestNoicon

{

    meta:

        description = "Rule to catch APKs with app name VideoTestNoicon"

    condition:

        androguard.app_name(/VideoTestNoicon/i)

}