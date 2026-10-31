$ErrorActionPreference = "Stop"

# --- manifest から version を取得 ---
$manifest = Get-Content "manifest.json" -Raw | ConvertFrom-Json
$version = $manifest.version

if (-not $version) {
    Write-Error "manifest.json に version がありません"
    exit 1
}

# --- 出力パス定義 ---
$outDir = ".release"
$fileName = "MailAuthInfoViewer-$version.xpi"
$outFile = Join-Path $outDir $fileName
$stageDir = Join-Path $outDir "_stage"

# --- クリーンアップ ---
New-Item -ItemType Directory -Force $outDir | Out-Null
if (Test-Path $outFile)  { Remove-Item -Force $outFile }
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }

# --- ステージング（階層維持） ---
New-Item -ItemType Directory -Force (Join-Path $stageDir "images") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $stageDir "lib") | Out-Null

Copy-Item -Force "manifest.json"     $stageDir
Copy-Item -Force "background.js"     $stageDir
Copy-Item -Force "qr_worker.js"      $stageDir
Copy-Item -Force "psl_data.js"       $stageDir
Copy-Item -Force "messagedisplay.js" $stageDir
Copy-Item -Force "options.html"      $stageDir
Copy-Item -Force "options.js"        $stageDir
Copy-Item -Force "LICENSE"           $stageDir
Copy-Item -Force "images/icon.svg"  (Join-Path $stageDir "images")
# サードパーティライブラリの情報ファイル
Copy-Item -Force "VENDOR.md"         $stageDir

# --- lib ディレクトリ（サードパーティライブラリ。入手方法は lib/README.md） ---
# qr_worker.js が読み込むため、無いままでは QR コード解析が動かない XPI になる
if (-not (Test-Path "lib/jsQR.js")) {
    Write-Error "lib/jsQR.js がありません。lib/README.md の手順で配置してください"
    exit 1
}
$libFiles = Get-ChildItem "lib/*.js", "lib/*.txt" -ErrorAction SilentlyContinue
foreach ($f in $libFiles) {
    Copy-Item -Force $f.FullName (Join-Path $stageDir "lib")
}

# --- _locales ディレクトリをコピー ---
Copy-Item -Recurse -Force "_locales" (Join-Path $stageDir "_locales")

# --- 圧縮 ---
Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $outFile -Force

# --- ステージ削除 ---
Remove-Item -Recurse -Force $stageDir

# --- SHA256 生成 ---
$hash = Get-FileHash $outFile -Algorithm SHA256
$hashFile = "$outFile.sha256"
"$($hash.Hash.ToLower())  $fileName" | Out-File -Encoding ascii $hashFile

# --- 出力 ---
Write-Host "Created: $outFile"
Write-Host "SHA256: $($hash.Hash)"
Write-Host "Checksum file created: $hashFile"
