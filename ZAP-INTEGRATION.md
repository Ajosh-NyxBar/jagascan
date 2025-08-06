# OWASP ZAP Integration Setup Guide

## Prerequisites
- OWASP ZAP 2.14.0 or higher
- JagaScan application running
- API Key: `4ke0djgc9n5v2mqv9582via78e`

## Quick Setup (Windows)

### 1. Install OWASP ZAP
```powershell
# Option 1: Download from official website
# Visit: https://www.zaproxy.org/download/

# Option 2: Using Chocolatey (if installed)
choco install zaproxy

# Option 3: Using Winget
winget install OWASP.ZAP
```

### 2. Configure ZAP API
1. Launch OWASP ZAP
2. Go to **Tools** → **Options** → **API**
3. Check **Enable API**
4. Set API Key: `4ke0djgc9n5v2mqv9582via78e`
5. Set listen address: `localhost:8080`
6. Click **OK** to save

### 3. Start ZAP in Daemon Mode (Optional)
```powershell
# Navigate to ZAP installation directory
cd "C:\Program Files\OWASP\Zed Attack Proxy"

# Start ZAP in daemon mode with API key
.\zap.bat -daemon -host localhost -port 8080 -config api.key=4ke0djgc9n5v2mqv9582via78e
```

### 4. Configure JagaScan
1. Copy environment file:
   ```powershell
   copy .env.example .env
   ```

2. Edit `.env` file with your settings:
   ```env
   ZAP_URL=http://localhost:8080
   ZAP_API_KEY=4ke0djgc9n5v2mqv9582via78e
   ```

3. Start JagaScan:
   ```powershell
   npm run dev
   ```

### 5. Test Integration
1. Open JagaScan: http://localhost:3000/scan
2. Expand **OWASP ZAP Integration** section
3. Enable ZAP integration
4. Click **Test Connection**
5. If successful, you'll see ✅ "Connected to ZAP"

## Usage

### Starting a ZAP-Enhanced Scan
1. Enter target URL (e.g., `http://testphp.vulnweb.com`)
2. Select scan types
3. Enable **OWASP ZAP Integration**
4. Configure advanced settings if needed:
   - Spider Max Depth: 5
   - Spider Max Children: 10
   - Enable Active Scanning: ✓
   - Enable Passive Scanning: ✓
5. Click **Start ZAP-Enhanced Scan**

### Monitoring Progress
- **Spider Phase**: Website crawling and discovery
- **Active Phase**: Vulnerability testing with payloads
- **Completed**: Security alerts available

### Viewing Results
- **Dashboard**: Overview of vulnerabilities found
- **Reports**: Detailed findings with remediation steps
- **Export**: PDF/HTML reports for sharing

## Test Targets

### Safe Testing Sites
- **DVWA**: http://dvwa.local (if installed)
- **WebGoat**: http://localhost:8080/WebGoat (if installed)
- **Mutillidae**: http://localhost/mutillidae (if installed)
- **Test PHP Site**: http://testphp.vulnweb.com

⚠️ **Warning**: Only test sites you own or have explicit permission to scan!

## Troubleshooting

### Connection Issues
```powershell
# Check if ZAP is running
netstat -an | findstr :8080

# Test ZAP API manually
curl http://localhost:8080/JSON/core/view/version/?apikey=4ke0djgc9n5v2mqv9582via78e
```

### Common Problems
1. **Port 8080 already in use**: Change ZAP port or stop conflicting service
2. **API key mismatch**: Ensure API key matches in both ZAP and JagaScan
3. **Firewall blocking**: Allow ZAP through Windows Firewall
4. **ZAP not responding**: Restart ZAP and wait for full initialization

### Enable Debug Logging
Add to `.env`:
```env
DEBUG=zap:*
LOG_LEVEL=debug
```

## Advanced Configuration

### Custom ZAP Policies
1. In ZAP: **Analyse** → **Scan Policy Manager**
2. Create custom policy
3. Use policy name in JagaScan advanced settings

### Proxy Configuration
Configure browser to use ZAP proxy:
- Host: `localhost`
- Port: `8081`
- Manual scan through proxy for authenticated testing

## Security Notes
- API key is transmitted in URL parameters - use HTTPS in production
- ZAP daemon should not be exposed to public networks
- Regularly update ZAP to latest version for security patches
- Review scan targets carefully to avoid unauthorized testing
