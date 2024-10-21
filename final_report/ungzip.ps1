#Accept payload in arg0
$base64=$args[0]
$base64Length = $base64 | Measure-Object -Character
#Print input length
write-host "Got payload - lenght: $($base64Length)"
#Extract bytes from base64 string
$bytes = [System.Convert]::FromBase64String($base64)
#Prepare stream to unzip it
$memoryStream = New-Object System.IO.MemoryStream(, $bytes)
$gzipStream = New-Object System.IO.Compression.GzipStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
$streamReader = New-Object System.IO.StreamReader($gzipStream)
$decompressedScript = $streamReader.ReadToEnd()
#Print ungzipped scipt
Write-Output $decompressedScript