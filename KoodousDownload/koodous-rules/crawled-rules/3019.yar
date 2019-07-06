
rule android_ransom_wannacry

{

    meta:

        description = "This rule detects wannacry lockscreen display ransomware"

        sample = "ba03c39ba851c2cb3ac5851b5f029b9c"

        reference = "https://nakedsecurity.sophos.com/2017/06/09/android-ransomware-hides-in-fake-king-of-glory-game/"


    strings:

        $a_1 = "biaozhunshijian"

        $a_2 = "Lycorisradiata"


    condition:


        all of ($a_*)


}