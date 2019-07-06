
rule detection

{

    strings:

        $d1 = "sqtwwitter.com"

        $d2 = "anqwtwitter.com"

        $d3 = "aqwtwitter.com"

        $d4 = "bstwwitter.com"

        $d5 = "qwtwitter.com"

        $d6 = "twitter.com"


        $ = /103.239.30.[0-9]{1,3}:7878/

        $ = /119.28.128.[0-9]{1,3}:7878/

        $ = /119.28.179.[0-9]{1,3}:7878/

        $ = /119.28.25.[0-9]{1,3}:7878/

        $ = /119.28.54.[0-9]{1,3}:7878/

        $ = /146.185.241.[0-9]{1,3}:7878/

        $ = /185.165.29.[0-9]{1,3}:7878/

        $ = /185.165.30.[0-9]{1,3}:7878/

        $ = /185.4.29.[0-9]{1,3}:7878/

        $ = /185.189.58.[0-9]{1,3}:7878/

        $ = /185.35.137.[0-9]{1,3}:7878/

        $ = /185.126.200.[0-9]{1,3}:7878/

        $ = /185.243.243.[0-9]{1,3}:7878/

        $ = /188.0.236.[0-9]{1,3}:7878/

        $ = /109.236.82.[0-9]{1,3}:7878/

        $ = /146.0.72.[0-9]{1,3}:7878/

        $ = /37.1.201.[0-9]{1,3}:7878/

        $ = /49.51.133.[0-9]{1,3}:7878/

        $ = /49.51.137.[0-9]{1,3}:7878/

        $ = /5.101.1.[0-9]{1,3}:7878/

        $ = /5.188.211.[0-9]{1,3}:7878/

        $ = /5.188.62.[0-9]{1,3}:7878/

        $ = /91.218.114.[0-9]{1,3}:7878/



    condition:

        1 of ($d*) and 1 of ($)




}