
rule PornSlocker

{

    meta:


        description = "http://blog.trendmicro.com/trendlabs-security-intelligence/first-kotlin-developed-malicious-app-signs-users-premium-sms-services/"


    strings:


        $ = "52.76.80.41"

        $ = "adx.gmpmobi.com"



    condition:


        all of them



}