
import "androguard"


rule LokiBot

{

    meta:

        description = "This rule will be able to tag all LokiBot samples"

        refernces = "https://www.threatfabric.com/blogs/lokibot_the_first_hybrid_android_malware.html"

        hash_1 = "1979d60ba17434d7b4b5403c7fd005d303831b1a584ea2bed89cfec0b45bd5c2"

        hash_2 = "a10f40c71721668c5050a5bf86b41a1d834a594e6e5dd82c39e1d70f12aadf8b"

        hash_3 = "86ffe2fa4a22e08c134b2287c232b5e46bd3f775274d795b1d526b6340915b5c  "

        author = "Jacob Soo Lead Re"

        date = "30-October-2017"

    condition:

        androguard.service(/CommandService/i)

        and androguard.receiver(/Boot/i) 

        and androguard.receiver(/Scrynlock/i) 

        and androguard.permission(/android\.permission\.BIND_DEVICE_ADMIN/i)

        and androguard.filter(/android\.app\.action\.DEVICE_ADMIN_ENABLED/i) 

}