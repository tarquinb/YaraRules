
rule fakeGames

{

    meta:

        sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

        google_play = "https://play.google.com/store/apps/developer?id=Dawerominza"


    strings:

        $a = "http://ggd.prnlivem.com/frerr.php"

        $b = "Lcom/gte/fds/j/a;"


    condition:

        any of them


}