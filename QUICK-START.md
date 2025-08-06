# Quick Start Guide - OWASP ZAP Integration

## 🚀 Setup dalam 5 Menit

### 1. Install Dependencies
```powershell
npm install
```

### 2. Setup Environment
```powershell
# Copy environment file
copy .env.example .env

# Edit .env dengan API key yang sudah disediakan:
# ZAP_API_KEY=4ke0djgc9n5v2mqv9582via78e
```

### 3. Install OWASP ZAP
```powershell
# Download: https://www.zaproxy.org/download/
# Atau gunakan Chocolatey:
choco install zaproxy
```

### 4. Konfigurasi ZAP
1. **Buka OWASP ZAP**
2. **Tools** → **Options** → **API**
3. **✓ Enable API**
4. **API Key**: `4ke0djgc9n5v2mqv9582via78e`
5. **OK**

### 5. Start Services
```powershell
# Terminal 1: Start JagaScan
npm run dev

# Terminal 2: Test ZAP Integration (opsional)
npm run demo:zap:windows
```

### 6. Akses Aplikasi
- **JagaScan**: http://localhost:3000
- **ZAP**: Pastikan berjalan di port 8080

## 🎯 Test Scan

1. **Buka**: http://localhost:3000/scan
2. **Target**: `http://testphp.vulnweb.com`
3. **Enable**: OWASP ZAP Integration ✓
4. **Click**: "Test Connection" (harus ✅)
5. **Start**: ZAP-Enhanced Scan

## 📊 Monitoring

- **Dashboard**: Real-time progress
- **Spider Phase**: Website crawling
- **Active Phase**: Vulnerability testing  
- **Results**: Detailed security findings

## 🛠️ Troubleshooting

### ZAP Connection Failed
```powershell
# Check ZAP status
netstat -an | findstr :8080

# Manual API test
curl "http://localhost:8080/JSON/core/view/version/?apikey=4ke0djgc9n5v2mqv9582via78e"
```

### Port 8080 Conflict
```powershell
# Find process using port 8080
netstat -ano | findstr :8080

# Kill process (if needed)
taskkill /PID [PID_NUMBER] /F
```

### API Key Mismatch
- Pastikan API key sama di ZAP dan JagaScan
- Restart ZAP setelah perubahan konfigurasi

## 🎯 Target Testing Aman

- **DVWA**: http://dvwa.local
- **Damn Vulnerable Web App**: http://testphp.vulnweb.com
- **WebGoat**: http://localhost:8080/WebGoat

⚠️ **PENTING**: Hanya test situs yang Anda miliki atau punya izin!

## 📁 File Struktur

```
jagascan/
├── src/
│   ├── components/ZAPIntegration.tsx    # UI komponen ZAP
│   ├── lib/zapClient.ts                 # ZAP API client
│   ├── lib/zapIntegration.ts           # Service layer
│   └── app/api/zap/                    # API endpoints
├── .env.example                        # Environment template  
├── ZAP-INTEGRATION.md                  # Dokumentasi lengkap
├── demo-zap-integration.ps1            # Demo script Windows
└── demo-zap-integration.sh             # Demo script Linux/Mac
```

## 🔗 Links

- **ZAP Download**: https://www.zaproxy.org/download/
- **ZAP Documentation**: https://www.zaproxy.org/docs/
- **JagaScan GitHub**: [Repository Link]
