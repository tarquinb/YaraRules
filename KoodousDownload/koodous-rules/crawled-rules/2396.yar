
rule Ransomware

{

    meta:

        description = "https://www.zscaler.de/blogs/research/new-android-ransomware-bypasses-all-antivirus-programs"



    strings:

        $a = "SHA1-Digest: xIzMBOypVosF45yRiV/9XQtugE0=" nocase



    condition:

        1 of them


}


rule Locker

{

    strings:

        $a = "SHA1-Digest: CbQPkm4OYwAEh3NogHhWeN7dA/o=" nocase


    condition:

        1 of them


}