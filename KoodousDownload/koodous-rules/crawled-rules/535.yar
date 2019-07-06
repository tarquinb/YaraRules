
rule Dendroid

{

    meta:

        description = "Dendroid RAT"

    strings:

        $s1 = "/upload-pictures.php?" wide ascii

        $s2 = "Opened Dialog:" wide ascii

        $s3 = "com/connect/MyService" wide ascii

        $s4 = "android/os/Binder" wide ascii

        $s5 = "android/app/Service" wide ascii

    condition:

        all of them


}


rule Dendroid_2

{

    meta:

        description = "Dendroid evidences via Droidian service"

    strings:

        $a = "Droidian" wide ascii

        $b = "DroidianService" wide ascii

    condition:

        all of them


}


rule Dendroid_3

{

    meta:

        description = "Dendroid evidences via ServiceReceiver"

    strings:

        $1 = "ServiceReceiver" wide ascii

        $2 = "Dendroid" wide ascii

    condition:

        all of them


}