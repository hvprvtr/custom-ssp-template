# unregister.ps1  -  откат регистрации. ЗАПУСКАТЬ ОТ АДМИНИСТРАТОРА, затем перезагрузка.
# Убирает "CustomSSP" из списка Security Packages и удаляет DLL из System32.

$ErrorActionPreference = 'Stop'
$pkg = 'CustomSSP'
$dst = "$env:WINDIR\System32\CustomSSP.dll"
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { throw 'Нужны права администратора.' }

function Remove-FromMultiSz($name) {
    $cur = (Get-ItemProperty $lsa -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $cur) { return }
    $new = [string[]]($cur | Where-Object { $_ -and $_ -ne $pkg })
    Set-ItemProperty $lsa -Name $name -Value $new -Type MultiString
    Write-Host "[-] '$pkg' убран из '$name' -> $($new -join ', ')"
}

Remove-FromMultiSz 'Security Packages'

Write-Host "[i] DLL в System32 удалим после перезагрузки (сейчас занята lsass, если была загружена)."
Write-Host "[i] Перезагрузись, затем при необходимости: Remove-Item '$dst' -Force"
if (Test-Path $dst) {
    try { Remove-Item $dst -Force; Write-Host "[-] Удалена $dst" }
    catch { Write-Warning "Не удалось удалить сейчас (занята). Удали после перезагрузки." }
}
