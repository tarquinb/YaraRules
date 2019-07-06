
rule Bot

{

    strings:

        $a = "/dodownload" ascii wide

        $b = "/dodelete" ascii wide

        $c = "/doupload" ascii wide

        $d = "/doprogress" ascii wide


    condition:

        all of them

}


rule Bot2

{

    strings:

        $a = "/download" ascii wide

        $b = "/delete" ascii wide

        $c = "/upload" ascii wide


    condition:

        all of them

}