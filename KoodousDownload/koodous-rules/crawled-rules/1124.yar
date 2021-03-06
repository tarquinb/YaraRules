
rule adware:aggressive {

    meta:

        description = "This rule detects an aggressive adware that shows in your screen applications to download"

        sample = "bd3629e451fb294b4573a6aad94ae6789e654d9ce8e8a5aae92095bf440a17cf"

        sample2 = "3d1524c836cf54a4391b2677adb5c287da180c6428e5d2f9f34bb80fb2fbd315"

    strings:

        $a = "assets/sys_channel.ngPK"

        $b = {6D 4B 6E E6 30 73 21 75 77 6F 55 36 21} //From assets/mend.png

    condition:

        all of them

}