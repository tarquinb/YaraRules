
rule FBI: ransomware

{

    meta:

        sample = "d7c5cb817adfa86dbc9d9c0d401cabe98a3afe85dad02dee30b40095739c540d"


    strings:

        $a = "close associates will be informed by the authorized FBI agents" wide ascii

        $b = "ed on the FBI Cyber Crime Department's Datacenter" wide ascii

        $c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar" wide ascii


    condition:

        all of them

}