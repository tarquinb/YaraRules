
rule SlemBunk

{

    meta:

        description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"

        sample = "4dd4a582071afb3081e8418b5b8178ef7ae256f9d5207c426bf7e5af2933ad20"

        source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"


    strings:

        $a = "#intercept_sms_start"

        $b = "#intercept_sms_stop"

        $c = "#block_numbers"

        $d = "#wipe_data"

        $e = "Visa Electron"


    condition:

        all of them


}