
import "file"

rule Faketoken : Test {

    meta: 

        description = "Ruleset to detect faketoken malware"


    condition:

        network.hosts = "185.48.56.239"



}