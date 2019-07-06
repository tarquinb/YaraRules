
import "androguard"


rule Android_Exaspy

{

    meta:

        author = "Jacob Soo Lead Re"

        date = "08-November-2016"

        description = "This rule will be able to tag all the Exaspy samples."

        source = "https://www.skycure.com/blog/exaspy-commodity-android-spyware-targeting-high-level-executives/"

    condition:

        (androguard.service(/\.protect\.MainService/i) and

        androguard.receiver(/\.protect\.utils\.receivers\.OnBootReceiver/i) and

        (androguard.url(/andr0idservices\.com/) or 

        androguard.url(/exaspy\.com/)))

}