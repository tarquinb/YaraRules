import "androguard"
import "file"
import "cuckoo"




rule medusah : packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"

  strings:
    $lib = "libmd.so"

  condition:
    $lib
}


rule medusah_appsolid : packer
{
  meta:
    // Samples and discussion: https://github.com/rednaga/APKiD/issues/19
    description = "Medusah (AppSolid)"
    url = "https://appsolid.co/"

  strings:
    $encrypted_dex = "assets/high_resolution.png"

  condition:
    $encrypted_dex and not medusah
}