$content = Get-Content 'server.js' -Raw
$oldStr = "const isPremium = req.user.role === 'premium';"
$newStr = "const isPremium = req.user.role === 'premium' || req.user.role === 'admin';"
$content = $content.Replace($oldStr, $newStr)
Set-Content 'server.js' $content -NoNewline
Write-Host "Done. Replaced all occurrences."
