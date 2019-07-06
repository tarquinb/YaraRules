
rule Ransom:Cokri {

    meta:

    description = "Trojan Locker Cokri"


    strings:

    $ = "com/example/angrybirds_test/MyService" 

    $ = "world4rus.com"

    $ = "api.php/?devise"


    condition:

    all of them


}