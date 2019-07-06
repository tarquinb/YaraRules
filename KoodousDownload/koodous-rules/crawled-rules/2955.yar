
import "androguard"



rule Dvmap

{

    //https://securelist.com/78648/dvmap-the-first-android-malware-with-code-injection/ 


    strings:

        $a = "com.colourblock.flood"


    condition:

        $a and not androguard.certificate.sha1("D75A495C4D7897534CC9910A034820ABD87D7F2F") 


}