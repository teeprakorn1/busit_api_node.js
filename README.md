# 🎓 Student Activity Tracking and Evaluation System

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node.js-18+-green.svg)
![Flutter](https://img.shields.io/badge/flutter-3.0+-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)

A comprehensive activity management system for Rajamangala University of Technology Tawan-Ok  
Faculty of Business Administration and Information Technology

[Features](#-features) • [Architecture](#-system-architecture) • [Installation](#-installation-guide) • [API Docs](#-api-documentation) • [Security](#-security-features)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Technology Stack](#-technology-stack)
- [Security Features](#-security-features)
- [Installation Guide](#-installation-guide)
- [Deployment](#-deployment-guide)
- [API Documentation](#-api-documentation)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌟 Overview

This project is a **Senior Project (Year 4, Semester 1)** aimed at modernizing student activity management at RMUTTO. The system provides:

- 📱 **Mobile Application (Flutter)** - For students and teachers to register, track, and manage activities
- 💻 **Admin Web Portal (React)** - Comprehensive dashboard for administrators
- 🤖 **AI Deepfake Detection (FastAPI + CNN)** - Validates authenticity of activity photos
- 🔌 **RESTful API Backend (Node.js + Express)** - Central hub connecting all components
- 🗄️ **Database & Cache (MySQL + Redis Cloud)** - Robust data management
- 📧 **Email & Push Notifications (Nodemailer + Firebase FCM)** - Real-time communication

### 🎯 Project Goals

- ✅ Streamline activity registration and attendance tracking
- ✅ Prevent fraudulent activity submissions using AI
- ✅ Provide real-time notifications and updates
- ✅ Ensure secure authentication and role-based access control
- ✅ Maintain comprehensive audit logs for accountability

---

## ✨ Features

### 🔐 Authentication & Authorization

- **Email-Based Login** - Secure authentication using university email addresses
- **OTP Password Recovery** - Forgot password functionality with email OTP verification
- **Role-Based Access Control (RBAC)** - Distinct permissions for:
  - 👨‍🎓 **Students** - Register for activities, view history, upload certificates
  - 👨‍🏫 **Teachers** - Approve activities, manage student submissions, view reports
  - 🤝 **Deans** - analytics, view all reports in deparment 
  - 👔 **Administrators** - Full system access, analytics, user management
- **JWT Access Tokens** - 1-day expiry with secure refresh mechanism
- **Secure Storage** - Flutter Secure Storage for sensitive mobile data

### 📱 Mobile Application (Flutter)

- Cross-platform support (Android/iOS)
- Activity browsing and registration
- QR code scanning for attendance
- Real-time push notifications (FCM)
- Certificate upload and management
- Activity history and statistics
- Offline-first architecture

### 💻 Admin Web Portal (React)

- Interactive dashboard with analytics
- User management (bulk import via CSV/Excel)
- Activity creation and approval workflow
- Department and faculty management
- Real-time activity monitoring
- Report generation and export
- Responsive design for desktop and mobile

### 🤖 AI-Powered Deepfake Detection

- **10 CNN Models (DenseNet)** - Ensemble prediction for high accuracy
- Multiple ensemble methods: Average, Voting, Max, Min
- Real-time image verification API
- Confidence scoring and statistics
- Prevents fake certificates and attendance fraud

### 🔔 Notification System

- **Push Notifications** - Firebase Cloud Messaging (FCM)
- **Email Notifications** - Activity updates, approvals, reminders
- **In-App Notifications** - Real-time activity feed

### 📊 Reporting & Analytics

- Activity participation statistics
- Department-wise performance metrics
- Student engagement tracking
- Export reports (PDF/Excel)

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Cloudflare DNS                          │
│                    (busitplus.com domain)                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Server + NGINX                       │
│              (Reverse Proxy + Let's Encrypt SSL)                │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   React Web  │  │  Node.js API │  │ FastAPI (AI) │           │
│  │  :443 (SSL)  │  │  :3000       │  │  :8000       │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │    MySQL     │ │ Redis Cloud  │ │   Firebase   │
        │   Database   │ │  (Tokens)    │ │     FCM      │
        └──────────────┘ └──────────────┘ └──────────────┘
                                │
                                ▼
                        ┌──────────────┐
                        │   Flutter    │
                        │   Mobile App │
                        └──────────────┘
```

### Component Responsibilities

| Component | Technology | Purpose |
|-----------|------------|---------|
| Mobile App | Flutter | Student/teacher interface for activity management |
| Admin Web | React | Administrative dashboard and management portal |
| API Server | Node.js + Express | RESTful API, authentication, business logic |
| AI Service | FastAPI + TensorFlow | Deepfake detection for uploaded images |
| Database | MySQL | Persistent data storage (users, activities, logs) |
| Cache | Redis Cloud | Token storage, session management |
| Push Notifications | Firebase FCM | Real-time notifications to mobile devices |
| Email Service | Nodemailer | OTP and notification emails |
| Web Server | NGINX | Reverse proxy, SSL termination, load balancing |
| DNS | Cloudflare | Domain management, DDoS protection, CDN |

---

## 🛠 Technology Stack

### 📱 Mobile Application

```yaml
Framework: Flutter (Dart)
Storage: Flutter Secure Storage
State Management: Provider / Riverpod
HTTP Client: Dio
Authentication: JWT + Secure Storage
Push Notifications: Firebase Cloud Messaging (FCM)
```

### 💻 Frontend (Admin Web)

```yaml
Framework: React.js
Styling: CSS Modules + Responsive Design
HTTP Client: Axios
Routing: React Router
Charts: Recharts / Chart.js
Data Encryption: CryptoJS
Build Tool: Create React App
```

### 🔌 Backend API

```yaml
Runtime: Node.js 18+
Framework: Express.js
Database ORM: MySQL2 (native driver)
Authentication: JWT (jsonwebtoken) + bcrypt
Security Middleware:
  - Helmet (HTTP headers)
  - CORS
  - express-rate-limit (brute force protection)
  - cookie-parser
  - sanitizeRequest (XSS, SQL injection prevention)
Logging: Winston
Email: Nodemailer
API Documentation: Swagger / OpenAPI 3.0
Process Manager: PM2
```

### 🤖 AI Service

```yaml
Framework: FastAPI (Python 3.9+)
ML Framework: TensorFlow 2.x
Model Architecture: DenseNet (10 ensemble models)
Image Processing: Pillow (PIL)
Server: Uvicorn (ASGI)
```

### 🗄 Database & Cache

```yaml
Primary Database: MySQL 8.0
  - Character Set: utf8mb4
  - Collation: utf8mb4_unicode_ci
  - Features: Transactions, Foreign Keys, Indexes
Cache Layer: Redis Cloud
  - Use Case: Token storage, OTP caching
  - Connection: TLS encrypted
```

### 🚀 DevOps & Infrastructure

```yaml
Server OS: Windows Server 2019/2022
Web Server: NGINX 1.24+
  - Features: Reverse proxy, SSL termination
SSL Certificates: Let's Encrypt (Certbot)
DNS Provider: Cloudflare
  - Features: DDoS protection, CDN, DNS management
Version Control: Git + GitHub
Monitoring: Winston Logs + Custom Analytics
```

---

## 🔒 Security Features

### 🛡️ Application Security

#### Authentication
- ✅ JWT Access Tokens - 1-day expiry, stored securely
- ✅ Bcrypt Password Hashing - Salted hashing for all user passwords
- ✅ OTP Email Verification - Time-limited codes for password recovery
- ✅ Session Management - Redis-based token blacklisting for logout

#### Authorization
- ✅ Role-Based Access Control (RBAC) - Granular permissions per role
- ✅ Route Protection - Middleware-level access control
- ✅ API Key Authentication - Swagger endpoint protection

#### Data Protection
- ✅ Input Validation - Schema validation for all requests
- ✅ Data Sanitization - Removes malicious payloads before processing
- ✅ Database Normalization - Prevents data redundancy and anomalies
- ✅ Encrypted Storage - Flutter Secure Storage for mobile app

### 🔐 Infrastructure Security

#### Network Security
- ✅ HTTPS Only - Let's Encrypt SSL certificates
- ✅ CORS Configuration - Whitelisted origins only
- ✅ Cloudflare Protection - DDoS mitigation and WAF
- ✅ Rate Limiting - Prevents brute force attacks

#### Server Hardening
- ✅ Helmet.js - Sets secure HTTP headers (CSP, HSTS, X-Frame-Options)
- ✅ NGINX Reverse Proxy - Hides backend infrastructure
- ✅ Firewall Rules - Port-level access control
- ✅ Secure Cookies - HttpOnly, Secure, SameSite flags

### 🛡️ Attack Prevention

| Attack Type | Prevention Mechanism |
|-------------|---------------------|
| SQL Injection | Parameterized queries, input sanitization |
| XSS (Cross-Site Scripting) | Output encoding, CSP headers, sanitizeRequest middleware |
| CSRF | SameSite cookies, CORS, token validation |
| Brute Force | express-rate-limit (max 100 requests/15min per IP) |
| DDoS | Cloudflare protection, rate limiting |
| Session Hijacking | Secure JWT storage, token rotation |
| Directory Traversal | Input validation, path sanitization |
| Deepfake Fraud | AI-powered image verification (10 CNN models) |

### 📜 Audit & Compliance

- ✅ Audit Logs - All user actions logged with timestamps
- ✅ Server Logs - Winston logging for requests, errors, and security events
- ✅ User Activity Tracking - Comprehensive history for accountability
- ✅ Error Handling - No sensitive info in error messages
- ✅ Secure Coding Practices - Following OWASP guidelines

---

## 📥 Installation Guide

### Prerequisites

Before starting, ensure you have:

- Node.js 18+ and npm
- Flutter SDK 3.0+
- Python 3.9+ (for AI service)
- MySQL 8.0+
- Git
- Windows Server (for production deployment)
- NGINX (for reverse proxy)

### 1️⃣ Clone Repositories

```bash
# Frontend - React Web Admin
git clone https://github.com/teeprakorn1/busit_web_react.git
cd busit_web_react

# Frontend - Flutter Mobile App
git clone https://github.com/teeprakorn1/busit_flutter_project.git
cd busit_flutter_project

# Backend - Node.js API
git clone https://github.com/teeprakorn1/busit_api_node.js.git
cd busit_api_node.js

# Backend - Python AI Service
git clone https://github.com/teeprakorn1/busit_ai_python.git
cd busit_ai_python
```

### 2️⃣ Setup Node.js API Backend

Navigate to backend directory:
```bash
cd busit_api_node.js
```

Install dependencies:
```bash
npm install
```

Create `.env` file:
```env
# Database Configuration
DATABASE_HOST=your-mysql-host.com
DATABASE_USER=your_db_user
DATABASE_PASS=your_secure_password
DATABASE_NAME=busitplus
DATABASE_PORT=3306

# Redis Configuration (Redis Cloud)
REDIS_HOST=your-redis-host.redns.redis-cloud.com
REDIS_PASS=your_redis_password
REDIS_USER=default
REDIS_TLS=true
REDIS_PORT=18295

# Email Configuration (Gmail SMTP)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your_app_specific_password

# Token Configuration
PRIVATE_TOKEN_KEY=your_jwt_secret_key_here_min_32_chars
SWAGGER_TOKEN_KEY=your_swagger_api_key_here

# Client URLs
WEB_CLIENT_URL_DEV=http://localhost:3001
WEB_CLIENT_URL_PROD=https://busitplus.com
WEB_CLIENT_URL_PROD_2=https://www.busitplus.com
COOKIE_DOMAIN_PROD=.busitplus.com

# Server Configuration
SERVER_PORT=3000
ENV_MODE=0  # 0: Development, 1: Production
```

Setup MySQL Database:
```sql
CREATE DATABASE IF NOT EXISTS busitplus 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Run migrations or import schema
SOURCE database/schema.sql;
```

Start the server:
```bash
# Development
npm run dev

# Production (with PM2)
pm2 start server.js --name busitplus-api
pm2 save
pm2 startup
```

### 3️⃣ Setup React Admin Web

Navigate to frontend directory:
```bash
cd busit_web_react
```

Install dependencies:
```bash
npm install
```

Create `.env` file:
```env
# Server Configuration
REACT_APP_SERVER_PROTOCOL=https://
REACT_APP_SERVER_BASE_URL=api.busitplus.com
REACT_APP_SERVER_PORT=:443

# Security Configuration
REACT_APP_SECREAT_KEY_CRYTO=your_crypto_secret_key_here

# API Endpoints
REACT_APP_API_VERIFY=/api/verifyToken-website
REACT_APP_API_LOGIN_WEBSITE=/api/login/website
REACT_APP_API_LOGOUT_WEBSITE=/api/logout-website
# ... (add other endpoints as needed)
```

Start development server:
```bash
npm start
```

Build for production:
```bash
npm run build
```

### 4️⃣ Setup Python AI Service

Navigate to AI directory:
```bash
cd busit_ai_python
```

Create virtual environment:
```bash
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Download/place your trained models:
```
models/
  ├── model_densenet_fold_bc_05_1_tf/
  ├── model_densenet_fold_bc_05_2_tf/
  ├── ...
  └── model_densenet_fold_bc_05_10_tf/
```

Start FastAPI server:
```bash
# Development
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 5️⃣ Setup Flutter Mobile App

Navigate to Flutter directory:
```bash
cd busit_flutter_project
```

Install dependencies:
```bash
flutter pub get
```

Configure Firebase FCM:
1. Download `google-services.json` (Android) and `GoogleService-Info.plist` (iOS) from Firebase Console
2. Place files in appropriate directories:
   - Android: `android/app/google-services.json`
   - iOS: `ios/Runner/GoogleService-Info.plist`

Update API endpoints in `lib/config/api_config.dart`:
```dart
class ApiConfig {
  static const String baseUrl = 'https://api.busitplus.com';
  static const String apiVersion = '/api';
  // ... other endpoints
}
```

Run the app:
```bash
# Check connected devices
flutter devices

# Run on specific device
flutter run -d <device_id>

# Build APK (Android)
flutter build apk --release

# Build iOS
flutter build ios --release
```

---

## 🚀 Deployment Guide

### Production Deployment on Windows Server

#### 1. Server Preparation

Install required software:
- Node.js 18+
- Python 3.9+
- MySQL 8.0
- NGINX
- Git

#### 2. NGINX Configuration

Create `nginx.conf`:

```nginx
worker_processes  4;

events {
    worker_connections  2048;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;
    client_max_body_size 50M;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;

    # React Web Admin (busitplus.com)
    server {
        listen 80;
        server_name busitplus.com www.busitplus.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name busitplus.com www.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        root C:/nginx/react-build;
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }

    # Node.js API (api.busitplus.com)
    server {
        listen 443 ssl http2;
        server_name api.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        location / {
            limit_req zone=api_limit burst=20 nodelay;
            
            proxy_pass http://localhost:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

    # Python AI Service (deepfake.busitplus.com)
    server {
        listen 443 ssl http2;
        server_name deepfake.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        location / {
            proxy_pass http://localhost:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_read_timeout 300s;
        }
    }
}
```

#### 3. Cloudflare DNS Configuration

```
A Record:   @              → Your_Server_IP (Proxied ✅)
A Record:   www            → Your_Server_IP (Proxied ✅)
A Record:   busitplus.com  → Your_Server_IP (Proxied ✅)
CNAME:      api            → busitplus.com (Proxied ✅)
CNAME:      deepfake       → busitplus.com (Proxied ✅)
```

Cloudflare Settings:
- SSL/TLS Mode: Full (strict)
- Always Use HTTPS: On
- Minimum TLS Version: TLS 1.2

#### 4. Start Services with PM2

```bash
# Node.js API
cd busit_api_node.js
pm2 start server.js --name busitplus-api
pm2 save

# Python AI Service
pm2 start "uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4" --name busitplus-ai --cwd C:/path/to/busit_ai_python

# Check status
pm2 status
pm2 logs busitplus-api
```

---

## 📚 API Documentation

### Access Swagger UI

- **Node.js API**: https://api.busitplus.com/api-docs
- **Python AI API**: https://deepfake.busitplus.com/docs
  
---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'feat: add feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

### Commit Message Convention
```
feat: New feature
fix: Bug fix
docs: Documentation update
refactor: Code restructuring
test: Add tests
```

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~100,000+ |
| **API Endpoints** | 80+ |
| **Database Tables** | 25 |
| **AI Models** | 10 (Ensemble) |
| **Supported Roles** | 4 (Student, Teacher, Dean, Admin) |
| **Mobile Platforms** | Android + iOS |
| **Test Coverage** | 90%+ |
| **Development Period** | 4 months |

---

## 🎓 Academic Information

**Project Type**: Senior Project (Capstone)  
**Academic Year**: 2024 (Year 4, Semester 1)  
**University**: Rajamangala University of Technology Tawan-Ok  
**Faculty**: Business Administration and Information Technology  
**Department**: Information Technology  

### Expected Outcomes
- ✅ 70% reduction in paperwork
- ✅ 87%+ accuracy in deepfake detection
- ✅ 75% faster activity registration process
- ✅ Real-time attendance verification
- ✅ Comprehensive audit trail and reporting

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact & Support

**Project Team**
- Email: busitplus.official@gmail.com
- Website: https://busitplus.com

**Support Channels**
- 📧 Email Support: busitplus.official@gmail.com
- 🐛 Bug Reports: [GitHub Issues](https://github.com/teeprakorn1/busit_api_node.js/issues)

---

## 🙏 Acknowledgments

Special thanks to:
- Project Advisor and University IT Department
- Rajamangala University of Technology Tawan-Ok : Chakrabongse Bhuvanarth Campus)
- Open Source Community (React.js, Flutter, Node.js, FastAPI, TensorFlow, MySQL, Redis, NGINX)

---

## 🗺 Roadmap

### Completed ✅
- ✅ Core authentication system (JWT + OTP)
- ✅ Role-based access control
- ✅ AI deepfake detection (10 models)
- ✅ Mobile app (Flutter) & Admin portal (React)
- ✅ Production deployment

### In Progress 🚧
- 🚧 Advanced analytics dashboard with AI

### Future Enhancements 🔮
- 🔮 Multi-language support (Thai/English)
- 🔮 Integration with university LMS

---

<div align="center">

### 🌟 Star this repository if you found it helpful!

**Made with ❤️ by RMUTTO Students**

![GitHub stars](https://img.shields.io/github/stars/teeprakorn1/busit_api_node.js?style=social)
![GitHub forks](https://img.shields.io/github/forks/teeprakorn1/busit_api_node.js?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/teeprakorn1/busit_api_node.js?style=social)

[⬆ Back to Top](#-student-activity-tracking-and-evaluation-system)

</div>
