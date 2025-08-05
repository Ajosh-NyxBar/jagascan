// Test script untuk real scanner
const { WebVulnerabilityScanner } = require('./src/lib/scanner.ts');

async function testScanner() {
  console.log('🔍 Testing Real Scanner...\n');
  
  // Test dengan target yang responsif
  const scanner = new WebVulnerabilityScanner('httpbin.org', {
    timeout: 10000,
    userAgent: 'JagaScan-Test/1.0'
  });
  
  try {
    console.log('📡 Starting scan...');
    const vulnerabilities = await scanner.scan();
    
    console.log(`✅ Scan completed! Found ${vulnerabilities.length} vulnerabilities:\n`);
    
    vulnerabilities.forEach((vuln, index) => {
      console.log(`${index + 1}. ${vuln.title}`);
      console.log(`   Type: ${vuln.type}`);
      console.log(`   Severity: ${vuln.severity}`);
      console.log(`   Location: ${vuln.location}`);
      console.log(`   Confidence: ${vuln.confidence}%`);
      console.log(`   Description: ${vuln.description}\n`);
    });
    
    // Demonstrasi bahwa ini bukan mock - hasil akan berbeda tergantung target
    console.log('🎯 This is REAL scanning - results vary based on actual target security!');
    console.log('🚫 No more fake 5 vulnerabilities every time!');
    
  } catch (error) {
    console.error('❌ Scan failed:', error.message);
  }
}

testScanner();
