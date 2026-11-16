# Preprod Docker validation for security fixes. Not for production.
# Usage: powershell -File tests/security/docker_preprod_validate.ps1
$ErrorActionPreference = 'Stop'
$Base = if ($env:JF_BASE) { $env:JF_BASE } else { 'http://127.0.0.1:8080' }
$UploadPass = if ($env:UPLOAD_PASSWORD) { $env:UPLOAD_PASSWORD } else { 'preprod-upload-secret' }
$AdminPass = if ($env:ADMIN_PASSWORD) { $env:ADMIN_PASSWORD } else { 'PreprodAdmin!2026Secure' }
$Tmp = Join-Path $env:TEMP ("jirafeau-preprod-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
$Pass = 0
$Fail = 0

function Note([string]$status, [string]$msg) {
    Write-Host "[$status] $msg"
    if ($status -eq 'PASS') { $script:Pass++ } elseif ($status -eq 'FAIL') { $script:Fail++ }
}

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string[]]$CurlArgs)
    & curl.exe -sS @CurlArgs
}

function Invoke-CurlCode {
    param([Parameter(Mandatory = $true)][string[]]$CurlArgs)
    & curl.exe -sS -o NUL -w '%{http_code}' @CurlArgs
}

function Invoke-CurlToFile {
    param(
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][string[]]$CurlArgs
    )
    & curl.exe -sS --output $OutFile @CurlArgs
}

try {
    Write-Host "== Health =="
    $code = Invoke-CurlCode -CurlArgs @("$Base/")
    if ($code -eq '200') { Note PASS "homepage HTTP $code" } else { Note FAIL "homepage HTTP $code" }

    Write-Host "== Compose restrictions (upload password) =="
    $nopassFile = Join-Path $Tmp 'nopass.txt'
    Set-Content -Path $nopassFile -Value 'no-pass' -NoNewline
    $nopass = Invoke-Curl -CurlArgs @('-F', "file=@$nopassFile;filename=nopass.txt", '-F', 'time=hour', "$Base/script.php")
    if ($nopass -match 'Error 2|Error 3') { Note PASS "upload without password refused" } else { Note FAIL "upload without password unexpected: $nopass" }

    Write-Host "== Classic upload + download password =="
    $classicFile = Join-Path $Tmp 'classic.txt'
    Set-Content -Path $classicFile -Value 'classic-upload-body' -NoNewline
    $up = Invoke-Curl -CurlArgs @('-F', "file=@$classicFile;filename=classic.txt", '-F', "upload_password=$UploadPass", '-F', 'time=hour', '-F', 'key=dl-secret-42', "$Base/script.php")
    $upLines = @($up -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($upLines.Count -ge 2 -and $upLines[0] -notmatch '^Error') {
        Note PASS "classic upload returned link+delete"
        $link = $upLines[0]
        $del = $upLines[1]
        $wrong = Invoke-Curl -CurlArgs @('-X', 'POST', '-F', 'key=wrong', "$Base/script.php?h=$link")
        if ($wrong -match 'Error 10') { Note PASS "download rejects wrong password" } else { Note FAIL "wrong password response: $wrong" }
        $okFile = Join-Path $Tmp 'classic-out.bin'
        Invoke-CurlToFile -OutFile $okFile -CurlArgs @('-X', 'POST', '-F', 'key=dl-secret-42', "$Base/script.php?h=$link")
        $got = [System.IO.File]::ReadAllText($okFile)
        if ($got -eq 'classic-upload-body') { Note PASS "download with correct password" } else { Note FAIL "download body mismatch: '$got'" }
        $delResp = & curl.exe -sS -X POST -H 'Content-Length: 0' "$Base/script.php?h=$link&d=$del"
        if ($delResp.Trim() -eq 'Ok') { Note PASS "delete via API" } else { Note FAIL "delete response: $delResp" }
        $gone = Invoke-Curl -CurlArgs @("$Base/script.php?h=$link")
        if ($gone -match 'Error 8') { Note PASS "link gone after delete" } else { Note FAIL "link still present: $gone" }
    } else {
        Note FAIL "classic upload failed: $up"
    }

    Write-Host "== Chunked (async) upload (inside container) =="
    $asyncLines = @(
        '#!/bin/sh'
        'set -e'
        "UP='$UploadPass'"
        'f1=/tmp/jf_c1.bin; f2=/tmp/jf_c2.bin'
        'printf CHUNK-A- > $f1'
        'printf CHUNK-B > $f2'
        'init=$(curl -sS -F upload_password=$UP -F filename=chunked.bin -F type=application/octet-stream -F time=hour "http://127.0.0.1/script.php?init_async")'
        'ref=$(printf %s "$init" | sed -n "1p")'
        'code=$(printf %s "$init" | sed -n "2p")'
        'p1=$(curl -sS -F "ref=$ref" -F "code=$code" -F "data=@$f1;filename=part1" "http://127.0.0.1/script.php?push_async")'
        'p2=$(curl -sS -F "ref=$ref" -F "code=$p1" -F "data=@$f2;filename=part2" "http://127.0.0.1/script.php?push_async")'
        'end=$(curl -sS -F "ref=$ref" -F "code=$p2" "http://127.0.0.1/script.php?end_async")'
        'link=$(printf %s "$end" | sed -n "1p")'
        'body=$(curl -sS "http://127.0.0.1/script.php?h=$link")'
        'echo "LINK=$link"'
        'echo "BODY=$body"'
        'del=$(printf %s "$end" | sed -n "2p")'
        'curl -sS -X POST -d "" "http://127.0.0.1/script.php?h=$link&d=$del" >/dev/null'
    )
    $asyncPath = Join-Path $Tmp 'async.sh'
    [System.IO.File]::WriteAllText($asyncPath, (($asyncLines -join "`n") + "`n"))
    docker compose cp $asyncPath web:/tmp/async.sh | Out-Null
    $asyncOut = docker compose exec -T web sh /tmp/async.sh
    Write-Host $asyncOut
    if ($asyncOut -match 'BODY=CHUNK-A-CHUNK-B' -and $asyncOut -match 'LINK=\S+') {
        Note PASS "async upload+download content intact"
    } else {
        Note FAIL "async failed: $asyncOut"
    }

    Write-Host "== One-time download =="
    $otFile = Join-Path $Tmp 'onetime.txt'
    Set-Content -Path $otFile -Value 'one-shot' -NoNewline
    $otUp = Invoke-Curl -CurlArgs @('-F', "file=@$otFile;filename=onetime.txt", '-F', "upload_password=$UploadPass", '-F', 'time=hour', '-F', 'one_time_download=1', "$Base/script.php")
    $otLines = @($otUp -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($otLines.Count -ge 1 -and $otLines[0] -notmatch '^Error') {
        $otLink = $otLines[0]
        $ot1 = Join-Path $Tmp 'ot1.bin'
        Invoke-CurlToFile -OutFile $ot1 -CurlArgs @("$Base/script.php?h=$otLink")
        $otBody = [System.IO.File]::ReadAllText($ot1)
        if ($otBody -eq 'one-shot') { Note PASS "one-time first download OK" } else { Note FAIL "one-time body='$otBody'" }
        $ot2 = Invoke-Curl -CurlArgs @("$Base/script.php?h=$otLink")
        if ($ot2 -match 'Error 8') { Note PASS "one-time second download refused" } else { Note FAIL "one-time still available: $ot2" }
    } else { Note FAIL "one-time upload: $otUp" }

    Write-Host "== HTTP 429 throttle (download password) =="
    $thFile = Join-Path $Tmp 'throttle.txt'
    Set-Content -Path $thFile -Value 'throttle-me' -NoNewline
    $thUp = Invoke-Curl -CurlArgs @('-F', "file=@$thFile;filename=throttle.txt", '-F', "upload_password=$UploadPass", '-F', 'time=hour', '-F', 'key=right-pass', "$Base/script.php")
    $thLines = @($thUp -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($thLines.Count -ge 2 -and $thLines[0] -notmatch '^Error') {
        $thLink = $thLines[0]
        $thDel = $thLines[1]
        $lastCode = ''
        for ($i = 0; $i -lt 6; $i++) {
            $lastCode = & curl.exe -sS -o NUL -w '%{http_code}' -X POST -F 'key=bad' "$Base/script.php?h=$thLink"
        }
        if ($lastCode -eq '429') { Note PASS "download password lockout returns HTTP 429" } else { Note FAIL "expected 429 after failures, got $lastCode" }
        $null = & curl.exe -sS -X POST -H 'Content-Length: 0' "$Base/script.php?h=$thLink&d=$thDel"
    } else { Note FAIL "throttle upload: $thUp" }

    Write-Host "== Admin IP restriction (from host) =="
    $adminHost = Invoke-Curl -CurlArgs @("$Base/admin.php")
    if ($adminHost -notmatch 'admin_password' -and $adminHost -notmatch "name='admin_password'") {
        Note PASS "admin from host denied by ADMIN_IP=127.0.0.1 (no login form)"
    } else {
        Note FAIL "admin login form visible from host despite ADMIN_IP"
    }

    Write-Host "== Admin login + clean + cookies (inside container) =="
    $adminSh = @'
#!/bin/sh
set -e
ADMIN_PASS='__ADMIN__'
COOKIE=/tmp/jf_admin.ck
rm -f "$COOKIE"
curl -sS -c "$COOKIE" -b "$COOKIE" http://127.0.0.1/admin.php -o /tmp/login.html
echo "LOGIN_FORM=$(grep -c admin_password /tmp/login.html || true)"
curl -sS -c "$COOKIE" -b "$COOKIE" -D /tmp/login.hdr -o /tmp/logged.html \
  -X POST --data-urlencode "admin_password=$ADMIN_PASS" http://127.0.0.1/admin.php
CSRF=$(grep -o "name='admin_csrf' value='[^']*'" /tmp/logged.html | head -1 | sed -n "s/.*value='\([^']*\)'.*/\1/p")
echo "CSRF_LEN=${#CSRF}"
echo "HAS_LOGOUT=$(grep -c logout /tmp/logged.html || true)"
if [ -z "$CSRF" ]; then echo ADMIN_CLEAN_FAIL; exit 0; fi
curl -sS -c "$COOKIE" -b "$COOKIE" -X POST \
  --data-urlencode "action=clean" \
  --data-urlencode "admin_csrf=$CSRF" \
  http://127.0.0.1/admin.php -o /tmp/clean.html
echo ADMIN_CLEAN_OK
curl -sS -D /tmp/ck_http.txt -o /dev/null -c /tmp/ck2.ck http://127.0.0.1/admin.php
echo "HTTP_COOKIE_LINE=$(tr -d '\r' < /tmp/ck_http.txt | grep -i set-cookie | tr '\n' ' ')"
curl -sS -D /tmp/ck_https.txt -o /dev/null -c /tmp/ck3.ck -H "X-Forwarded-Proto: https" http://127.0.0.1/admin.php
echo "HTTPS_COOKIE_LINE=$(tr -d '\r' < /tmp/ck_https.txt | grep -i set-cookie | tr '\n' ' ')"
'@ -replace '__ADMIN__', $AdminPass
    $adminPath = Join-Path $Tmp 'admin.sh'
    [System.IO.File]::WriteAllText($adminPath, ($adminSh -replace "`r`n", "`n"))
    docker compose cp $adminPath web:/tmp/admin.sh | Out-Null
    $adminOut = docker compose exec -T web sh /tmp/admin.sh
    Write-Host $adminOut
    if ($adminOut -match 'LOGIN_FORM=[1-9]') { Note PASS "admin login form reachable from 127.0.0.1 inside container" } else { Note FAIL "admin form not reachable inside container" }
    if ($adminOut -match 'ADMIN_CLEAN_OK') { Note PASS "admin login+CSRF clean from 127.0.0.1" } else { Note FAIL "admin clean flow failed" }
    if ($adminOut -match 'HTTPS_COOKIE_LINE=.*(?i)Secure') {
        Note PASS "Secure cookie set behind trusted PROXY_IP + X-Forwarded-Proto=https"
    } else {
        Note FAIL "Secure cookie missing with trusted proxy HTTPS"
    }
    if ($adminOut -match 'HTTP_COOKIE_LINE=.*(?i)Secure') {
        Note FAIL "Secure cookie unexpectedly set on plain HTTP"
    } else {
        Note PASS "plain HTTP session cookie without Secure"
    }
    if ($adminOut -match '(?i)HttpOnly') {
        Note PASS "HttpOnly present on session cookie"
    } else {
        Note FAIL "HttpOnly missing on session cookie"
    }

    Write-Host "== Internal files inaccessible =="
    foreach ($path in @('/install.php', '/lib/config.local.php', '/lib/functions.php', '/lib/settings.php')) {
        $c = Invoke-CurlCode -CurlArgs @("$Base$path")
        if ($c -eq '403' -or $c -eq '404') { Note PASS "$path HTTP $c (blocked)" } else { Note FAIL "$path HTTP $c (should be blocked)" }
    }
    $js = Invoke-CurlCode -CurlArgs @("$Base/lib/functions.js.php")
    if ($js -eq '200') { Note PASS "/lib/functions.js.php HTTP 200 (allowed UI asset)" } else { Note FAIL "/lib/functions.js.php HTTP $js" }
    $cVar = Invoke-CurlCode -CurlArgs @("$Base/var-files/")
    if ($cVar -eq '403' -or $cVar -eq '404') { Note PASS "/var-files/ HTTP $cVar (blocked)" } else { Note FAIL "/var-files/ HTTP $cVar" }

    Write-Host "== Untrusted X-Forwarded-Proto from host =="
    $spoofHdr = Join-Path $Tmp 'spoof.hdr'
    & curl.exe -sS -D $spoofHdr -o NUL -H 'X-Forwarded-Proto: https' "$Base/admin.php"
    $spoofLine = ((Get-Content $spoofHdr) | Where-Object { $_ -match '^(?i)set-cookie:' }) -join ' '
    if ($spoofLine -match '(?i)secure') {
        Note FAIL "host request with spoofed X-Forwarded-Proto got Secure cookie"
    } else {
        Note PASS "spoofed X-Forwarded-Proto from host does not set Secure"
    }

} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$Pass passed, $Fail failed"
if ($Fail -gt 0) { exit 1 } else { exit 0 }
