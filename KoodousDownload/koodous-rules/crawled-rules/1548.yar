
import "droidbox"


rule example_droidbox

{

    meta:

        description = "This is aexample for Droidbox Ruleset, these numbers are presents in malware"


    condition:

        droidbox.sendsms("18258877494") or droidbox.sendsms("12114")


}