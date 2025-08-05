# JagaScan - Web Security Scanner

A professional web-based penetration testing tool for identifying vulnerabilities in web applications and networks.

## 🎯 Project Overview

JagaScan is a comprehensive security scanning platform built with Next.js 15, TypeScript, and Tailwind CSS. It provides automated vulnerability assessment capabilities with real-time progress tracking and detailed reporting.

## ✨ Phase 1 Features (MVP - Complete)

- ✅ **Dashboard Overview**: Real-time statistics and vulnerability distribution charts
- ✅ **URL/Domain Input Form**: Advanced target configuration with validation
- ✅ **Basic Web Vulnerability Scanning**: OWASP Top 10 detection
- ✅ **Real-time Scan Progress**: Live progress tracking with detailed status updates
- ✅ **Report Generation**: Multiple format support (PDF/HTML/JSON)
- ✅ **Scan History**: Complete scan management and filtering
- ✅ **Dark Theme UI**: Professional security tools interface
- ✅ **Toast Notifications**: User-friendly feedback system

## 🛠 Tech Stack

- **Frontend**: Next.js 15 + TypeScript + Tailwind CSS
- **UI Components**: Headless UI + Lucide React Icons
- **Charts**: Recharts for data visualization
- **Backend**: Next.js API Routes
- **Database**: In-memory database (development) / SQLite/PostgreSQL (production)
- **Styling**: Tailwind CSS with custom dark theme

## 🚀 Getting Started

### Prerequisites

- Node.js 18.17 or later
- npm or yarn package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd jagascan
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start development server**
   ```bash
   npm run dev
   ```

4. **Open your browser**
   Navigate to [http://localhost:3000](http://localhost:3000)

## 📱 Application Structure

```
src/
├── app/                    # Next.js App Router
│   ├── dashboard/         # Dashboard pages
│   ├── scan/             # Scanning interface
│   ├── reports/          # Reports pages
│   ├── api/              # API routes
│   │   ├── scan/         # Scanning endpoints
│   │   ├── reports/      # Reports endpoints
│   │   └── dashboard/    # Dashboard endpoints
│   └── globals.css       # Global styles
├── components/           # Reusable UI components
│   ├── Alert.tsx         # Alert component
│   ├── Charts.tsx        # Chart components
│   ├── LoadingSpinner.tsx
│   ├── Navbar.tsx        # Navigation component
│   ├── ScanProgress.tsx  # Real-time progress tracker
│   └── Toast.tsx         # Notification system
├── lib/                  # Core business logic
│   ├── database.ts       # Database layer
│   ├── scanner.ts        # Scanner implementations
│   └── scannerService.ts # Enhanced scanner service
├── types/                # TypeScript type definitions
│   └── index.ts          # Main type definitions
└── utils/                # Utility functions
    └── index.ts          # Helper functions
```

## 🔍 Available Scan Types

### Phase 1 (Current)
- **Web Vulnerability Scan**: OWASP Top 10 detection
- **Port Scanning**: Network service discovery
- **SSL/TLS Analysis**: Certificate and configuration analysis
- **SQL Injection Testing**: Database security assessment
- **XSS Detection**: Cross-site scripting vulnerability detection
- **Directory Enumeration**: Hidden file and folder discovery

### Phase 2 (Coming Soon)
- Custom payload injection
- API endpoint testing
- Authenticated scanning
- Multi-target scanning
- Advanced reporting options

## 🎨 UI/UX Features

- **Dark Theme**: Professional security tools aesthetic
- **Real-time Updates**: Live scan progress with WebSocket-like polling
- **Interactive Charts**: Vulnerability distribution and scan activity visualization
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Toast Notifications**: Non-intrusive user feedback
- **Advanced Filtering**: Scan history with multiple filter options

## 🔒 Security Features

- **Input Validation**: Comprehensive target URL/domain validation
- **Rate Limiting**: Built-in protection against abuse
- **Scan Authorization**: Security checks for legitimate targets only
- **Result Sanitization**: XSS protection in scan results
- **Error Handling**: Graceful error management and logging

## 📊 API Endpoints

### Scan Management
- `POST /api/scan` - Start new scan
- `GET /api/scan` - List all scans
- `GET /api/scan/[id]` - Get specific scan details
- `GET /api/scan/[id]/progress` - Get real-time scan progress
- `DELETE /api/scan/[id]` - Delete scan

### Reports
- `POST /api/reports` - Generate report
- `GET /api/reports` - List available reports
- `GET /api/reports/[id]` - Download report

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

## 🧪 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint

### Environment Variables

Create a `.env.local` file in the root directory:

```env
NODE_ENV=development
API_BASE_URL=http://localhost:3000
```

## 🚀 Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Connect your repository to Vercel
3. Deploy automatically

### Manual Deployment

1. Build the application
   ```bash
   npm run build
   ```

2. Start the production server
   ```bash
   npm start
   ```

## 📝 Development Roadmap

### Phase 2 (Advanced Features)
- [ ] Network scanning enhancements
- [ ] Custom payload management
- [ ] API endpoint testing
- [ ] Authenticated scanning
- [ ] Multi-target scanning
- [ ] Advanced export options

### Phase 3 (Professional Features)
- [ ] User authentication system
- [ ] Role-based access control
- [ ] Scan scheduling
- [ ] Integration with external tools (OWASP ZAP, Nmap)
- [ ] Team collaboration features
- [ ] Advanced reporting dashboard

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Legal Notice

**IMPORTANT**: This tool is designed for authorized security testing only. 

- Only scan targets you own or have explicit permission to test
- Unauthorized scanning may violate laws and terms of service
- Users are responsible for compliance with applicable laws and regulations
- The developers are not responsible for misuse of this tool

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📧 Support

For support, please open an issue on GitHub or contact the development team.

---

**Built with ❤️ for cybersecurity professionals**
