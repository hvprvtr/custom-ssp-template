# register.ps1  -  установка custom SSP-пакета. ЗАПУСКАТЬ ОТ АДМИНИСТРАТОРА.
#
# Что делает:
#   1) копирует out\build\x64-release\CustomSSP.dll в C:\Windows\System32
#   2) добавляет "CustomSSP" в список Security Packages (роль SSP)
# После этого НУЖНА ПЕРЕЗАГРУЗКА — список читается при старте lsass.exe.
#
# Примечание: это ЧИСТЫЙ SSP — в Authentication Packages он НЕ добавляется
# (AP-роль вынесена в отдельный проект). Для итеративной проверки без реестра
# и без ребута используй tools\ssp_load.exe (AddSecurityPackage).

$ErrorActionPreference = 'Stop'
$pkg = 'CustomSSP'
$src = Join-Path $PSScriptRoot '..\out\build\x64-release\CustomSSP.dll'
$dst = "$env:WINDIR\System32\CustomSSP.dll"
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# --- проверка прав администратора ---
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { throw 'Нужны права администратора. Запусти PowerShell от имени администратора.' }

# --- предупреждение про LSA Protection (PPL) ---
$ppl = (Get-ItemProperty $lsa -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
if ($ppl) {
    Write-Warning "RunAsPPL=$ppl : включена защита LSA. Неподписанный пакет lsass НЕ загрузит."
    Write-Warning "Для учебной ВМ отключи: Remove-ItemProperty '$lsa' -Name RunAsPPL ; затем перезагрузка."
}

# --- 1) копируем DLL ---
Copy-Item $src $dst -Force
Write-Host "[+] DLL скопирована: $dst"

# --- helper: добавить значение в REG_MULTI_SZ без дублей ---
function Add-ToMultiSz($name) {
    $cur = (Get-ItemProperty $lsa -Name $name -ErrorAction SilentlyContinue).$name
    $cur = @([string[]]$cur | Where-Object { $_ -ne '' })   # ВСЕГДА массив (иначе скаляр -> конкатенация строк)
    if ($cur -contains $pkg) {
        Write-Host "[=] '$pkg' уже в '$name'"
    } else {
        $new = [string[]]($cur + $pkg)                       # добавляем элементом массива
        Set-ItemProperty $lsa -Name $name -Value $new -Type MultiString
        Write-Host "[+] '$pkg' добавлен в '$name' -> $($new -join ', ')"
    }
}

Add-ToMultiSz 'Security Packages'         # роль SSP

Write-Host ""
Write-Host "[i] Готово. ПЕРЕЗАГРУЗИ систему, чтобы lsass подхватил пакет:"
Write-Host "      Restart-Computer"
