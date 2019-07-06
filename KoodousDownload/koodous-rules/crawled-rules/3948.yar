
import "androguard"

import "cuckoo"



rule YaYaGene: rule1 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "03 Jan 2018"

        url = "https://koodous.com/apks?search=be44cc5f3ec413f649154a515725fff58fd87fb47fd83201577872c2594b7f84%20OR%20%209548ee4acd88262a084aba5bac2002746fff85ed83008c9cdf2a13199ab77aa6%20OR%20%20d70fa70efbff55eafc9077bc6ed49798d5cf966a2a0cb8062ff6ffb5c688773c%20OR%20%20014996cc63ed7ba6118149166290303df1dce4daaf27a194222746e9160dcfaa%20OR%20%20dc96d4230bb489acd3b823b22345626d0e0ac8ba48871f8fa864974ba504faec%20OR%20%2075759cc9af54e71ac79fbdc091e30b4a6e5d5862d2b1c0decfb83c9a3d99b01b%20OR%20%20ad03a820f5458977d1a8621c7a64722e08bf85acdbbca23bae345aa4e573a0eb%20OR%20%20621e6eb85c67f4af9eb5a3a5afee99f5a797d84cb606bb2bfc8d387517fb08ba%20OR%20%20b902c0cb656addf4fbd5c6b1836233445e9e1775944a0b0551e1e2d4cfd87372"


    condition:


        androguard.url("http://192.168.100.4:8101") or 


        (androguard.url("http://91.226.11.200") or 

        cuckoo.network.dns_lookup(/91\.226\.11\.200/)  or 

        cuckoo.network.http_request(/91\.226\.11\.200/)) or 


        androguard.url("http://91.226.11.200/pl/alior/index.html") or 


        androguard.url("http://91.226.11.200/pl/bzwbk/index.html") or 


        androguard.url("http://91.226.11.200/pl/ingbank/index.html") or 


        androguard.url("http://91.226.11.200/pl/mbank/index.html") or 


        androguard.url("http://91.226.11.200/pl/millennium/index.html") or 


        androguard.url("http://91.226.11.200/pl/pekao/index.html") or 


        androguard.url("http://91.226.11.200/pl/pkobp/index.html") or 


        androguard.url("http://91.226.11.200/pl/plusonline/index.html") or 


        androguard.url("http://91.226.11.200/pl/raiffeisen/index.html") or 


        androguard.url("http://91.226.11.200/pl/smartbank/index.html")

}