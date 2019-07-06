
import "droidbox"


rule SMSSender

{

    meta:

        description = "SMS Sender"


    condition:

        droidbox.sendsms(/./)

        and not droidbox.sendsms("122")

}