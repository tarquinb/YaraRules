
rule ExaSpySimple

{

    meta:

        description = "https://www.skycure.com/blog/exaspy-commodity-android-spyware-targeting-high-level-executives/"

        sample = "fee19f19638b0f66ba5cb32c229c4cb62e197cc10ce061666c543a7d0bdf784a"


    strings:

        $a = "andr0idservices.com" nocase


    condition:

        $a


}