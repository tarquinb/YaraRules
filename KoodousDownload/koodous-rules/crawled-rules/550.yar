
//41dce59ace9cce668e893c9d2c35d6859dc1c86d631a0567bfde7d34dd5cae0b

//61f7909512c5caf6dd125659428cf764631d5a52c59c6b50112af4a02047774c

//2c89d0d37257c90311436115c1cf06295c39cd0a8c117730e07be029bd8121a0

rule moscow_fake : banker

{

    meta:

        description = "Moskow Droid Development"

        thread_level = 3

        in_the_wild = true


    strings:

        $string_a = "%ioperator%"

        $string_b = "%imodel%"

        $string_c = "%ideviceid%"

        $string_d = "%ipackname%"

        $string_e = "VILLLLLL"


    condition:

        all of ($string_*)

}