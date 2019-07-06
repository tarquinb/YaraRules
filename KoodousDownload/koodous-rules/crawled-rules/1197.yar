
rule russian_domain: adware

{

    strings:

        $a = "zzwx.ru"


    condition:

        $a


}