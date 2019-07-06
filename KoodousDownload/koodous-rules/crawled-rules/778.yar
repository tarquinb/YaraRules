
import "androguard"


rule certifigate : teamviewer

{

    meta:

        description = "This rule detects applications with the same serial number than TeamViewer certificate"

        sample = "db1ee3a8af6fc808aecc0fbe1a36c04c8f9a28a744dc540e21669b493375aacd" //TeamViewer official app

        source = "https://www.blackhat.com/docs/us-15/materials/us-15-Bobrov-Certifi-Gate-Front-Door-Access-To-Pwning-Millions-Of-Androids.pdf"


    strings:

        $a = {03 02 01 02 02 04 4C C0 1B 8D} 

        //{03 02 01 02 02 04} is the preamble to serial cert

        //{4C C0 1B 8D} cert in hex. In signed 32 bit is: 806159881 (teamviewer app)


    condition:

        $a

        and not androguard.certificate.sha1("3E22144E1BA9151C08838D4C5EFF236DB48AAA32") //Excluding TV official


}