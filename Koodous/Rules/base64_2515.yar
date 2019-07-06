rule bas64
{
  strings:
      $b64 = "base64_decode"
  condition:
      $b64    
}