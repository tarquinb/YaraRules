
import "androguard"


rule boibaSender

{

    meta:

        description = "Collects info and sends SMS to contacts. Usually faking Candy Crush"


    strings:

        $a = "http://vinaaz.net/check/game.txt"

        $b = "http://192.168.1.12:8080/BoiBaiServer/services/BoiBaiTayRemoteImpl"

        $c = "http://sms_service/boibaitay/"

    condition:

        $a or $b or $c


}