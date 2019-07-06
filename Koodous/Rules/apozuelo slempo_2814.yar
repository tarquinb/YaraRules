rule slempo_detectado
{
        meta:
                description = "Trojan-Banker.Slempo"

        strings:
                $a = "org/slempo/service" nocase


        condition:
                1 of them
}