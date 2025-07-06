# __________________________________________________________________________________
#
# Tricks with Trojan's v1.0 - Interactive Security Toolkit
# Created by: Emircan Akalın
#
# Bu script, sistem analizi ve temel tehdit müdahalesi için tasarlanmıştır.
# This script is designed for system analysis and basic threat response.
# __________________________________________________________________________________

#region Script Configuration and Initialization

# --- Global Değişkenler (Global Variables) ---
$baseDir = "C:\TricksWithTrojans"
$quarantineDir = Join-Path -Path $baseDir -ChildPath "Quarantine"
$backupDir = Join-Path -Path $baseDir -ChildPath "Backups"
$reportPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\TWT_Analysis_Report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
$htmlReport = @() # Raporu oluşturmak için HTML parçalarını tutar (Holds HTML fragments to build the report)

# --- Ortamı Hazırlama (Initialize Environment) ---
function Initialize-Environment {
    Write-Host "`nOrtam hazırlanıyor... (Initializing environment...)" -ForegroundColor Yellow
    # Gerekli klasörler yoksa oluştur
    # Create necessary directories if they don't exist
    $requiredDirs = @($baseDir, $quarantineDir, $backupDir)
    foreach ($dir in $requiredDirs) {
        if (-not (Test-Path -Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    # HTML Rapor Başlığını Oluştur
    # Create HTML Report Header
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<title>Tricks with Trojan's v1.0 | Analiz Raporu (Analysis Report)</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; background-color: #f4f4f9; color: #333; }
    h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #3498db; color: white; }
    tr:nth-child(even) { background-color: #ecf0f1; }
    .section { background-color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .summary { background-color: #eaf2f8; border-left: 5px solid #3498db; padding: 15px; }
</style>
</head>
<body>
<h1>Tricks with Trojan's v1.0 - Analiz Raporu (Analysis Report)</h1>
<div class='summary'>
    <strong>Rapor Tarihi (Report Date):</strong> $(Get-Date)<br>
    <strong>Kullanıcı (User):</strong> $env:USERNAME<br>
    <strong>Bilgisayar (Computer):</strong> $env:COMPUTERNAME
</div>
"@
    $script:htmlReport += $htmlHeader
}

# --- Raporlama Fonksiyonları (Reporting Functions) ---
function Add-ToReport {
    param(
        [string]$Title,
        [PSCustomObject[]]$Content
    )
    $htmlSection = "<div class='section'><h2>$Title</h2>"
    if ($Content) {
        $htmlSection += $Content | ConvertTo-Html -Fragment
    } else {
        $htmlSection += "<p>Bu kategoride herhangi bir bulguya rastlanmadı. (No findings in this category.)</p>"
    }
    $htmlSection += "</div>"
    $script:htmlReport += $htmlSection
}

function Export-Report {
    $script:htmlReport += "</body></html>"
    $script:htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "`n✓ Rapor oluşturuldu! (Report generated!) -> $reportPath" -ForegroundColor Green
}
#endregion

#region Analysis and Detection Modules

function Clear-TemporaryFiles {
    Write-Host "`n[+] TEMP klasörleri temizleniyor... (Cleaning TEMP folders...)" -ForegroundColor Cyan
    try {
        $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp")
        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "✓ Geçici dosyalar temizlendi. (Temporary files cleaned.)" -ForegroundColor Green
    } catch {
        Write-Warning "Bazı geçici dosyalar temizlenemedi. (Could not clean some temporary files.)"
    }
}

# UYGULANAN DEĞİŞİKLİK - Bu fonksiyon kullanıcıya tarama seçeneği sunacak şekilde güncellendi.
# APPLIED CHANGE - This function was updated to offer scan options to the user.
function Start-DefenderScan {
    Write-Host "`n[+] Windows Defender Taraması (Windows Defender Scan)" -ForegroundColor Cyan
    $scanChoice = Read-Host "Tarama türünü seçin - [1] Hızlı (Quick) veya [2] Tam (Full): (Choose scan type - [1] Quick or [2] Full):"
    
    if ($scanChoice -eq "1") {
        Write-Host "Hızlı tarama başlıyor... Bu işlem birkaç dakika sürebilir. (Quick scan starting... This may take several minutes.)" -ForegroundColor Yellow
        try {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop | Out-Null
            Write-Host "✓ Hızlı tarama tamamlandı. (Quick scan completed.)" -ForegroundColor Green
        } catch {
            Write-Error "Defender Hızlı Tarama başarısız oldu: $_ (Defender Quick Scan failed: $_)"
        }
    } elseif ($scanChoice -eq "2") {
        Write-Host "Tam tarama başlıyor... Bu işlem saatler sürebilir, sabırlı olun. (Full scan starting... This can take hours, please be patient.)" -ForegroundColor Yellow
        try {
            Start-MpScan -ScanType FullScan -ErrorAction Stop | Out-Null
            Write-Host "✓ Tam tarama tamamlandı. (Full scan completed.)" -ForegroundColor Green
        } catch {
            Write-Error "Defender Tam Tarama başarısız oldu: $_ (Defender Full Scan failed: $_)"
        }
    } else {
        Write-Warning "Geçersiz seçim. İşlem iptal edildi. (Invalid choice. Operation cancelled.)"
    }
}

function Get-HostsFileEntries {
    Write-Host "`n[+] hosts dosyası kontrol ediliyor... (Checking hosts file...)" -ForegroundColor Cyan
    $hostsPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\drivers\etc\hosts"
    $content = Get-Content $hostsPath | Where-Object { $_ -match '^\s*\d' -and $_ -notmatch 'localhost' } | ForEach-Object {
        [PSCustomObject]@{
            Entry = $_
        }
    }
    Add-ToReport -Title "Hosts Dosyası Analizi (Hosts File Analysis)" -Content $content
}

function Get-SuspiciousWinEvents {
    Write-Host "`n[+] Şüpheli Windows Olay Günlükleri taranıyor... (Scanning for suspicious Windows Event Logs...)" -ForegroundColor Cyan
    $events = @()
    # Yeni Servis Yüklemeleri (New Service Installations) - Son 7 gün (Last 7 days)
    $events += Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message
    # Çok Sayıda Başarısız Oturum Açma (Multiple Failed Logons)
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
    if ($failedLogons.Count -gt 20) {
        $events += [PSCustomObject]@{TimeCreated=(Get-Date); Message="UYARI: Son 24 saatte $($failedLogons.Count) başarısız oturum açma denemesi! (WARNING: $($failedLogons.Count) failed login attempts in the last 24 hours!)"}
    }
    Add-ToReport -Title "Şüpheli Olay Günlükleri (Suspicious Event Logs)" -Content $events
}

function Find-RecentExecutables {
    Write-Host "`n[+] Kullanıcı klasörlerinde yeni oluşturulmuş programlar aranıyor... (Searching for recent executables in user folders...)" -ForegroundColor Cyan
    $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
    $extensions = @("*.exe", "*.bat", "*.ps1", "*.vbs", "*.scr")
    $files = Get-ChildItem -Path $scanPaths -Include $extensions -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, CreationTime, Length
    Add-ToReport -Title "Son 7 Günde Oluşturulan Şüpheli Dosyalar (Suspicious Files Created in Last 7 Days)" -Content $files
}

function Get-StartupItems {
    Write-Host "`n[+] Başlangıç öğeleri listeleniyor... (Listing startup items...)" -ForegroundColor Cyan
    $startupItems = @()
    # Kayıt Defteri (Registry)
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $regPaths) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Type = 'Registry'
                    Name = $_.Name
                    Command = $_.Value
                    Source = $path
                }
            }
        }
    }
    # Klasör (Folder)
    $folderPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($path in $folderPaths) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $startupItems += [PSCustomObject]@{
                Type = 'Folder'
                Name = $_.Name
                Command = $_.FullName
                Source = $path
            }
        }
    }
    Add-ToReport -Title "Başlangıçta Çalışan Programlar (Startup Programs)" -Content $startupItems
    
    # Eyleme geçme (Take action)
    if ($startupItems) {
        if ((Read-Host "`nBulunan başlangıç öğelerinden herhangi birini silmek ister misiniz? (E/H) (Do you want to remove any of the found startup items? (Y/N))").ToLower() -eq 'e' -or 'y') {
            $nameToRemove = Read-Host "Lütfen silmek istediğiniz öğenin tam 'Name'ini girin (Please enter the exact 'Name' of the item to remove)"
            $itemToRemove = $startupItems | Where-Object { $_.Name -eq $nameToRemove } | Select-Object -First 1
            if ($itemToRemove) {
                Remove-StartupItem -Item $itemToRemove
            } else {
                Write-Warning "Bu isimde bir öğe bulunamadı. (Item with this name not found.)"
            }
        }
    }
}

function Get-NetworkConnections {
    Write-Host "`n[+] Aktif ağ bağlantıları listeleniyor... (Listing active network connections...)" -ForegroundColor Cyan
    $connections = netstat -ano | Select-String "ESTABLISHED" | ForEach-Object {
        $parts = $_.Line -split '\s+'
        if ($parts.Count -gt 4) {
            $process = Get-Process -Id $parts[5] -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Protocol = $parts[1]
                LocalAddress = $parts[2]
                ForeignAddress = $parts[3]
                State = $parts[4]
                PID = $parts[5]
                ProcessName = $process.ProcessName
            }
        }
    }
    Add-ToReport -Title "Aktif Ağ Bağlantıları (Active Network Connections)" -Content $connections

    if ($connections) {
        if ((Read-Host "`nBu bağlantılardan birini kuran işlemi sonlandırmak ister misiniz? (E/H) (Do you want to terminate a process for one of these connections? (Y/N))").ToLower() -eq 'e' -or 'y') {
            $pidToStop = Read-Host "Lütfen sonlandırmak istediğiniz işlemin PID'sini girin (Please enter the PID of the process to terminate)"
            $processToStop = Get-Process -Id $pidToStop -ErrorAction SilentlyContinue
            if ($processToStop) {
                Write-Warning "UYARI: '$($processToStop.ProcessName)' (PID: $pidToStop) işlemini sonlandırmak üzeresiniz. Bu işlem sistem kararsızlığına yol açabilir."
                Write-Warning "WARNING: You are about to terminate '$($processToStop.ProcessName)' (PID: $pidToStop). This could cause system instability."
                if ((Read-Host "Emin misiniz? (E/H) (Are you sure? (Y/N))").ToLower() -eq 'e' -or 'y') {
                    Stop-Process -Id $pidToStop -Force
                    Write-Host "✓ İşlem sonlandırıldı. (Process terminated.)" -ForegroundColor Green
                }
            } else {
                Write-Warning "Bu PID ile bir işlem bulunamadı. (Process with this PID not found.)"
            }
        }
    }
}

#endregion

#region Action and Remediation Modules

function Quarantine-File {
    Write-Host "`n[+] Dosya Karantinaya Alma (Quarantine File)" -ForegroundColor Cyan
    $target = Read-Host "Karantinaya alınacak dosyanın tam yolunu girin (Enter full path of the file to quarantine)"
    if (Test-Path $target) {
        try {
            $fileName = Split-Path -Path $target -Leaf
            $quarantinePath = Join-Path -Path $quarantineDir -ChildPath "$fileName-$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
            Move-Item -Path $target -Destination $quarantinePath -Force -ErrorAction Stop
            Write-Host "✓ Dosya karantinaya alındı! (File quarantined!) -> $quarantinePath" -ForegroundColor Green
        } catch {
            Write-Error "Dosya karantinaya alınamadı: $_ (Failed to quarantine file: $_)"
        }
    } else {
        Write-Warning "Dosya bulunamadı. (File not found.)"
    }
}

function Remove-StartupItem {
    param([PSCustomObject]$Item)
    
    Write-Warning "UYARI: '$($Item.Name)' başlangıç öğesini sileceksiniz. (WARNING: You are about to delete the startup item '$($Item.Name)'.)"
    if ((Read-Host "Devam etmek istiyor musunuz? (E/H) (Do you want to continue? (Y/N))").ToLower() -ne 'e' -and 'y') {
        Write-Host "İşlem iptal edildi. (Operation cancelled.)"
        return
    }

    try {
        if ($Item.Type -eq 'Registry') {
            # Önce yedekle (Backup first)
            $keyPath = $Item.Source.Replace("HKEY_CURRENT_USER", "HKCU:").Replace("HKEY_LOCAL_MACHINE", "HKLM:")
            $backupFile = Join-Path -Path $backupDir -ChildPath "$($Item.Name.Replace(' ','_'))_$(Get-Date -Format 'yyyyMMddHHmmss').reg"
            $regPathForExport = $Item.Source.Replace("HKCU:\", "HKEY_CURRENT_USER\").Replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
            reg export $regPathForExport $backupFile /y | Out-Null
            Write-Host "Yedek oluşturuldu: $backupFile (Backup created: $backupFile)" -ForegroundColor Yellow
            
            # Sil (Delete)
            Remove-ItemProperty -Path $Item.Source -Name $Item.Name -Force -ErrorAction Stop
        } elseif ($Item.Type -eq 'Folder') {
            # Klasördeki dosyaları karantinaya al (Quarantine files from folder)
            $fileName = Split-Path -Path $Item.Command -Leaf
            $quarantinePath = Join-Path -Path $quarantineDir -ChildPath "$fileName-$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
            Move-Item -Path $Item.Command -Destination $quarantinePath -Force -ErrorAction Stop
        }
        Write-Host "✓ Başlangıç öğesi başarıyla kaldırıldı. (Startup item removed successfully.)" -ForegroundColor Green
    } catch {
        Write-Error "Öğe kaldırılamadı: $_ (Failed to remove item: $_)"
    }
}

#endregion

#region Main Menu and Execution

function Show-Menu {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════╗"
    Write-Host "║           Tricks with Trojan's v1.0 - Interactive Toolkit            ║"
    Write-Host "║                       Created by Emircan Akalın                      ║"
    Write-Host "╚══════════════════════════════════════════════════════════════════════╝"
    Write-Host "`nLütfen bir seçenek belirtin: (Please select an option:)"
    
    Write-Host "`n--- Hızlı Araçlar (Quick Tools) ---"
    Write-Host " 1) Geçici Dosyaları Temizle (Clear Temporary Files)"
    # UYGULANAN DEĞİŞİKLİK - Menü metni güncellendi.
    # APPLIED CHANGE - The menu text was updated.
    Write-Host " 2) Windows Defender Taraması Başlat (Seçenekli) (Start Defender Scan (with options))"
    Write-Host " 3) Dosyayı Karantinaya Al (Quarantine a File)"
    
    Write-Host "`n--- Analiz ve Tespit Modülleri (Analysis & Detection Modules) ---"
    Write-Host " 4) Başlangıç Öğelerini Analiz Et (Analyze Startup Items)"
    Write-Host " 5) Aktif Ağ Bağlantılarını Göster (Show Active Network Connections)"
    Write-Host " 6) Hosts Dosyasını Kontrol Et (Check Hosts File)"
    Write-Host " 7) Şüpheli Olay Günlüklerini Tara (Scan Suspicious Event Logs)"
    Write-Host " 8) Yeni Oluşturulmuş Şüpheli Dosyaları Bul (Find Recent Suspicious Files)"
    
    Write-Host "`n--- Toplu İşlemler (Batch Operations) ---"
    Write-Host " 9) TÜM ANALİZLERİ ÇALIŞTIR ve Raporla (RUN ALL ANALYSES and Report)"
    
    Write-Host "`n Q) Çıkış (Exit)"
}

function Main {
    # Yönetici yetkisi kontrolü
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Warning "Bu script'i Yönetici olarak çalıştırmalısınız! (You must run this script as Administrator!)"
        Pause; return
    }
    
    Initialize-Environment

    do {
        Show-Menu
        $choice = Read-Host "`nSeçiminiz (Your choice)"
        
        switch ($choice) {
            '1' { Clear-TemporaryFiles }
            '2' { Start-DefenderScan }
            '3' { Quarantine-File }
            '4' { Get-StartupItems }
            '5' { Get-NetworkConnections }
            '6' { Get-HostsFileEntries }
            '7' { Get-SuspiciousWinEvents }
            '8' { Find-RecentExecutables }
            '9' {
                Write-Host "`n[***] TÜM ANALİZLER ÇALIŞTIRILIYOR... (RUNNING ALL ANALYSES...) [***]`n" -ForegroundColor Magenta
                Get-StartupItems
                Get-NetworkConnections
                Get-HostsFileEntries
                Get-SuspiciousWinEvents
                Find-RecentExecutables
                Export-Report
            }
            'q' { Write-Host "Çıkılıyor... (Exiting...)" }
            default { Write-Warning "Geçersiz seçim. Lütfen tekrar deneyin. (Invalid choice. Please try again.)" }
        }

        if ($choice -ne 'q') {
            Write-Host "`nDevam etmek için bir tuşa basın... (Press any key to continue...)"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }

    } while ($choice -ne 'q')
}

# Script'i Başlat (Start the Script)
Main

#endregion