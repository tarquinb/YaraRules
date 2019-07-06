
import "androguard"




rule rusSMS

{

    meta:

        description = "Russian app, connects to remote server (http://googlesyst.com/) and gets the user to answer SMS (and a fake funds balance). Apparently, to unlock the app you have to send reiterate SMS."


    strings:

        // Both domains (GoogleSyst is not official afaik. registered on the same place)

        $a = "http://googlesyst.com/"

        $b = "mxclick.com"


    condition:

        $a and $b


}