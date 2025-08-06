# OWASP ZAP Troubleshooting Guide

## ❌ Error: "Unable to connect to ZAP"

### Root Cause
Meskipun ZAP berjalan di port 8080, API ZAP belum dikonfigurasi dengan benar.

### 🔧 Solusi Step-by-Step

### 1. **Cek Status ZAP API**
```powershell
# Test koneksi ke ZAP
netstat -an | findstr :8080

# Test API ZAP
Invoke-RestMethod -Uri "http://localhost:8080/JSON/core/view/version/?apikey=4ke0djgc9n5v2mqv9582via78e"
```

### 2. **Konfigurasi ZAP API (PENTING!)**

#### A. Buka OWASP ZAP
1. **Start** → **OWASP ZAP**
2. Pilih **Start with a script** atau **No, I do not want to persist this session**

#### B. Aktifkan API
1. **Tools** → **Options**
2. **API** di menu kiri
3. **✓ Enable API**
4. **API Key**: `4ke0djgc9n5v2mqv9582via78e`
5. **Listen Address**: `localhost` (atau `*` untuk semua interface)
6. **Listen Port**: `8080`
7. **✓ Secure Headers** (opsional, tapi direkomendasikan)
8. **OK**

#### C. Restart ZAP
1. **File** → **Exit**
2. Start ulang ZAP
3. Tunggu sampai UI fully loaded

### 3. **Test API Connection**
```powershell
# Setelah konfigurasi, test lagi
Invoke-RestMethod -Uri "http://localhost:8080/JSON/core/view/version/?apikey=4ke0djgc9n5v2mqv9582via78e"

# Harus return response seperti:
# {"version":"2.14.0"}
```

### 4. **Alternative: Start ZAP Daemon Mode**
```powershell
# Navigate ke ZAP directory
cd "C:\Program Files\OWASP\Zed Attack Proxy"

# Start ZAP daemon dengan API aktif
.\zap.bat -daemon -host localhost -port 8080 -config api.key=4ke0djgc9n5v2mqv9582via78e -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Tunggu message: "ZAP is now listening on localhost:8080"
```

### 5. **Verify Integration di JagaScan**
1. Buka: http://localhost:3000/scan
2. Expand **OWASP ZAP Integration**
3. **✓ Enable ZAP**
4. Click **Test Connection**
5. Harus show: **✅ Connected to ZAP - Version: 2.14.0**

## 🚨 Common Issues

### Issue 1: API Key Mismatch
**Error**: `API key missing or invalid`
**Solution**: 
- Pastikan API key sama di ZAP dan JagaScan
- Copy exact: `4ke0djgc9n5v2mqv9582via78e`

### Issue 2: Port Conflict
**Error**: `Address already in use`
**Solution**:
```powershell
# Find process using port 8080
netstat -ano | findstr :8080

# Kill process (if not ZAP)
taskkill /PID [PID_NUMBER] /F
```

### Issue 3: Firewall Blocking
**Error**: `Connection timeout`
**Solution**:
1. **Windows Firewall** → **Allow an app**
2. Add **OWASP ZAP** to allowed apps
3. Allow both **Private** and **Public** networks

### Issue 4: ZAP Not Fully Started
**Error**: `Connection refused`
**Solution**:
- Wait 30-60 seconds after starting ZAP
- Look for "ZAP is now listening" message
- Check ZAP status bar shows "Ready"

## 📋 Quick Fix Commands

```powershell
# Complete setup in one go
# 1. Kill any conflicting process
Get-Process | Where-Object {$_.ProcessName -like "*java*"} | Stop-Process -Force

# 2. Start ZAP daemon
cd "C:\Program Files\OWASP\Zed Attack Proxy"
Start-Process -FilePath ".\zap.bat" -ArgumentList "-daemon", "-host", "localhost", "-port", "8080", "-config", "api.key=4ke0djgc9n5v2mqv9582via78e"

# 3. Wait and test
Start-Sleep -Seconds 30
Invoke-RestMethod -Uri "http://localhost:8080/JSON/core/view/version/?apikey=4ke0djgc9n5v2mqv9582via78e"
```

## 💡 Pro Tips

1. **Start ZAP first**, then JagaScan
2. Use **ZAP GUI** untuk first-time setup, daemon untuk production
3. Check **ZAP logs** untuk error details: `View` → `Show Log Tabs`
4. API harus **aktif dan accessible** sebelum test JagaScan integration

## 🎯 Expected Success Output

Setelah setup benar:
```json
{
  "version": "2.14.0"
}
```

JagaScan integration test:
```
✅ Connected to ZAP - Version: 2.14.0
✅ ZAP API responds correctly
✅ Ready for enhanced scanning
```

---

💡 **Jika masih error**, screenshot ZAP configuration dan paste error message untuk troubleshooting lebih lanjut.
