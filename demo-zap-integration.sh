#!/bin/bash

# OWASP ZAP Integration Demo Script for JagaScan
# This script demonstrates ZAP integration capabilities

API_KEY="4ke0djgc9n5v2mqv9582via78e"
ZAP_URL="http://localhost:8080"
JAGASCAN_URL="http://localhost:3000"

echo "🛡️  JagaScan OWASP ZAP Integration Demo"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if a service is running
check_service() {
    local url=$1
    local name=$2
    
    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ $name is running${NC}"
        return 0
    else
        echo -e "${RED}❌ $name is not running${NC}"
        return 1
    fi
}

# Function to test ZAP API
test_zap_api() {
    echo -e "${BLUE}🔍 Testing ZAP API connection...${NC}"
    
    local response=$(curl -s "$ZAP_URL/JSON/core/view/version/?apikey=$API_KEY" 2>/dev/null)
    
    if echo "$response" | grep -q "version"; then
        local version=$(echo "$response" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}✅ ZAP API connected - Version: $version${NC}"
        return 0
    else
        echo -e "${RED}❌ ZAP API connection failed${NC}"
        echo "Response: $response"
        return 1
    fi
}

# Function to start ZAP scan
start_zap_scan() {
    local target=$1
    echo -e "${BLUE}🚀 Starting ZAP-enhanced scan for: $target${NC}"
    
    local scan_payload=$(cat << EOF
{
  "target": "$target",
  "scanTypes": ["web_vulnerability"],
  "options": {
    "maxDepth": 3,
    "followRedirects": true,
    "timeout": 30000
  },
  "zapConfig": {
    "zapUrl": "$ZAP_URL",
    "apiKey": "$API_KEY",
    "spiderMaxDepth": 5,
    "spiderMaxChildren": 10,
    "enableActiveScan": true,
    "enablePassiveScan": true
  }
}
EOF
)

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$scan_payload" \
        "$JAGASCAN_URL/api/zap/scan")
    
    if echo "$response" | grep -q '"success":true'; then
        local scan_id=$(echo "$response" | grep -o '"scanId":"[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}✅ Scan started successfully${NC}"
        echo "Scan ID: $scan_id"
        return 0
    else
        echo -e "${RED}❌ Failed to start scan${NC}"
        echo "Response: $response"
        return 1
    fi
}

# Function to check scan progress
check_progress() {
    local scan_id=$1
    echo -e "${BLUE}📊 Checking scan progress...${NC}"
    
    local response=$(curl -s "$JAGASCAN_URL/api/zap/scan?scanId=$scan_id&zapUrl=$ZAP_URL&apiKey=$API_KEY")
    
    if echo "$response" | grep -q '"success":true'; then
        local progress=$(echo "$response" | grep -o '"progress":[0-9]*' | cut -d':' -f2)
        local phase=$(echo "$response" | grep -o '"phase":"[^"]*"' | cut -d'"' -f4)
        local current_task=$(echo "$response" | grep -o '"currentTask":"[^"]*"' | cut -d'"' -f4)
        
        echo -e "${YELLOW}Phase: $phase${NC}"
        echo -e "${YELLOW}Progress: $progress%${NC}"
        echo -e "${YELLOW}Current Task: $current_task${NC}"
        
        return $progress
    else
        echo -e "${RED}❌ Failed to get progress${NC}"
        return 1
    fi
}

# Main demo flow
main() {
    echo -e "${BLUE}Step 1: Checking services...${NC}"
    
    # Check if JagaScan is running
    if ! check_service "$JAGASCAN_URL" "JagaScan"; then
        echo -e "${YELLOW}Please start JagaScan: npm run dev${NC}"
        exit 1
    fi
    
    # Check if ZAP is running
    if ! check_service "$ZAP_URL" "OWASP ZAP"; then
        echo -e "${YELLOW}Please start OWASP ZAP on port 8080${NC}"
        echo "Attempting to start ZAP automatically..."
        
        # Try to start ZAP in background (if installed)
        if command -v zap.sh >/dev/null 2>&1; then
            echo "Starting ZAP daemon..."
            zap.sh -daemon -host localhost -port 8080 -config api.key=$API_KEY &
            sleep 10
            
            if ! check_service "$ZAP_URL" "OWASP ZAP"; then
                echo -e "${RED}Failed to start ZAP automatically${NC}"
                exit 1
            fi
        else
            echo -e "${RED}ZAP not found in PATH. Please start manually.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${BLUE}Step 2: Testing ZAP API...${NC}"
    if ! test_zap_api; then
        echo -e "${YELLOW}Make sure ZAP API is enabled with key: $API_KEY${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 3: Starting demo scan...${NC}"
    local target="http://testphp.vulnweb.com"
    echo "Target: $target"
    
    if start_zap_scan "$target"; then
        echo -e "${GREEN}🎉 Demo completed successfully!${NC}"
        echo -e "${BLUE}Next steps:${NC}"
        echo "1. Open JagaScan: $JAGASCAN_URL/scan"
        echo "2. Monitor scan progress in the dashboard"
        echo "3. View results when scan completes"
    else
        echo -e "${RED}❌ Demo failed${NC}"
        exit 1
    fi
    
    echo -e "\n${BLUE}📋 Demo Summary:${NC}"
    echo "• JagaScan: ✅ Running"
    echo "• OWASP ZAP: ✅ Connected"
    echo "• API Integration: ✅ Working"
    echo "• Demo Scan: ✅ Started"
    echo ""
    echo -e "${GREEN}Integration is working correctly!${NC}"
}

# Run the demo
main "$@"
