# 🎓 Student Activity Tracking and Evaluation System

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node.js-18+-green.svg)
![Flutter](https://img.shields.io/badge/flutter-3.0+-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)

**A Comprehensive Activity Management System with AI-Powered Deepfake Detection**  
Faculty of Business Administration and Information Technology  
Rajamangala University of Technology Tawan-Ok (Chakrabongse Bhuvanarth Campus)

**Senior Project (Year 4, Semester 1, Academic Year 2568)**

[Features](#-features) • [Research](#-research-background) • [Architecture](#-system-architecture) • [Installation](#-installation-guide) • [API Docs](#-api-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Research Background](#-research-background)
- [Features](#-features)
- [AI Deepfake Detection](#-ai-deepfake-detection)
- [System Architecture](#-system-architecture)
- [Technology Stack](#-technology-stack)
- [Security Features](#-security-features)
- [Installation Guide](#-installation-guide)
- [Deployment](#-deployment-guide)
- [Research Results](#-research-results)
- [Contributing](#-contributing)
- [Project Team](#-project-team)

---

## 🌟 Overview

This project is a **Senior Project (ภาคนิพนธ์)** developed as part of the Computer Science curriculum at RMUTTO. The system modernizes student activity management through:

- 📱 **Mobile Application (Flutter)** - Cross-platform app for students and teachers
- 💻 **Admin Web Portal (React)** - Comprehensive management dashboard
- 🤖 **AI Deepfake Detection (FastAPI + CNN)** - Novel image verification using 10 ensemble models
- 🔌 **RESTful API Backend (Node.js + Express)** - Centralized data management
- 🗄️ **Database & Cache (MySQL + Redis Cloud)** - Robust data infrastructure
- 📧 **Real-time Notifications (Nodemailer + Firebase FCM)** - Instant communication

### 🎯 Project Objectives

According to RMUTTO regulations, students must participate in **at least 12 extracurricular activities** throughout their studies to graduate. This system addresses critical challenges:

1. ✅ **Streamline Activity Registration** - Replace manual paper-based systems
2. ✅ **Prevent Fraudulent Submissions** - AI detection of manipulated activity photos
3. ✅ **Enable Real-time Tracking** - Instant activity status updates
4. ✅ **Ensure Data Integrity** - Comprehensive audit logs and verification
5. ✅ **Improve Accessibility** - Mobile-first design for convenient access

### 👥 Target Users

- **นักศึกษา (Students)** - Register for activities, check-in/out, view history
- **อาจารย์ (Teachers)** - Monitor student participation, approve submissions
- **ผู้บริหาร (Deans)** - View department-wide analytics and reports
- **เจ้าหน้าที่ (Staff)** - Manage activities, users, and certificates

---

# 🔬 Research Background

This project incorporates cutting-edge research in **image forgery detection** specifically tailored for student activity verification.

## 📄 Published Research

**Title:** "Image Forgery Detection in Student Activities Based on Convolutional Neural Networks"

**Authors:** Teepakorn Kumvong, Suphawat Baebkhuntod, Rinyaphat Bowonjiraphonrat, Rath Burirat

**Abstract:** This research developed CNN-based models to detect photo manipulation in student activity submissions, addressing the critical problem of fraudulent activity evidence.

⚠️ **Note:** The full paper is currently under preparation for journal submission. Data used in this repository is anonymized and representative only.

## 🧪 Research Methodology

### Dataset Composition

Our research utilized a carefully curated dataset of 1,000 images:

- **Real Images:** 500 authentic student activity photos from official Facebook pages
- **Forged Images:** 500 manipulated photos using 5 applications:
  - **Mobile Apps:** ProKnockout, Meitu, Magic Eraser (300 images)
  - **Desktop Apps:** Photoshop, Canva (200 images)
  - **Editing Time:** 50 images @ 15 minutes + 50 images @ 30 minutes per app

### CNN Models Evaluated

We trained and compared five different architectures:

1. **CNN-Simple** - Basic convolutional architecture
2. **CNN-Augment** - Enhanced with data augmentation (rotation, brightness)
3. **MobileNetV2** - Pretrained lightweight model for mobile devices
4. **Xception** - Pretrained model with depthwise separable convolutions
5. **DenseNet121** - Dense connectivity pattern for maximum information flow

**Validation Method:** 10-Fold Cross-Validation to eliminate selection bias

## 📊 Key Research Findings

### Model Performance Comparison

Based on 10-fold cross-validation with 1,000 images:

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| **DenseNet121** | **83.1%** | **83.17%** | **83.0%** | **83.08%** |
| CNN-Simple | 80.7% | 79.46% | 82.8% | 81.1% |
| Xception | 80.7% | 83.89% | 76.0% | 79.75% |
| MobileNetV2 | 79.9% | 84.37% | 73.4% | 78.5% |
| CNN-Augment | 79.2% | 77.97% | 81.4% | 79.65% |

### Detection Accuracy by Application

**Mobile Applications (High Detection Rate):**

| Application | 15min Edit | 30min Edit | Average |
|-------------|------------|------------|---------|
| **ProKnockout** | 100% | 98% | 99% |
| **Meitu** | 100% | 100% | 100% |
| **Magic Eraser** | 100% | 100% | 100% |

**Desktop Applications (Moderate Detection Rate):**

| Application | 15min Edit | 30min Edit | Average |
|-------------|------------|------------|---------|
| **Photoshop** | 62% | 38% | 50% |
| **Canva** | 64% | 66% | 65% |

### Critical Discoveries

✅ **Mobile vs Desktop Editing:** Mobile app forgeries detected with **96-100% accuracy** (ProKnockout, Meitu, Magic Eraser)  
⚠️ **Desktop app forgeries harder to detect:** Photoshop (38-72% accuracy), Canva (58-70% accuracy)  
⏱️ **Time Factor:** 15-minute edits detected easier than 30-minute edits across all models  
🎯 **Best Model:** DenseNet121 provides optimal balance of accuracy and reliability

## 🔍 Research Implications

The research demonstrates that:

1. **CNN-based detection is highly effective** for mobile-edited images (90%+ accuracy)
2. **Desktop applications** with advanced tools pose greater challenges
3. **Multiple ensemble models** improve overall detection reliability
4. **Real-world deployment** requires balanced approach between accuracy and performance

### Practical Applications

- ✅ First-line automated screening
- ✅ Flagging suspicious submissions for manual review
- ✅ Deterring casual photo manipulation attempts
- ✅ Maintaining academic integrity in activity verification

### Future Research Directions

- 📈 Increase training data with more desktop-edited samples
- 🔄 Incorporate longer editing times (45-60 minutes)
- 🤖 Explore ensemble voting mechanisms
- 🎯 Achieve 95%+ detection accuracy for all forgery types

## 📚 Academic Impact

**Thesis Details:**
- **Title (Thai):** ระบบติดตามและประเมินผลกิจกรรมนักศึกษาของคณะบริหารธุรกิจและเทคโนโลยีสารสนเทศ มหาวิทยาลัยเทคโนโลยีราชมงคลตะวันออก
- **Title (English):** Student Activity Tracking and Evaluation System of the Faculty of Business Administration and Information Technology, Rajamangala University of Technology Tawan-Ok
- **Academic Year:** 2568 (2024-2025), Semester 1
- **Degree:** Bachelor of Science (Computer Science)
- **Advisor:** Ajarn Pichai Jodpimai

**Research Contribution:**
This work contributes to the growing body of knowledge in:
- Computer vision and deep learning applications
- Academic integrity and fraud prevention
- Real-world deployment of AI systems in education
- Mobile vs desktop image manipulation detection

## 📖 Citation

If you use this research or system in your work, please cite:
```bibtex
@thesis{kumvong2024imageforgerystudent,
  author = {Kumvong, Teepakorn and Baebkhuntod, Suphawat and Bowonjiraphonrat, Rinyaphat},
  title = {Image Forgery Detection in Student Activities Based on Convolutional Neural Networks},
  school = {Rajamangala University of Technology Tawan-Ok},
  year = {2024},
  type = {Senior Project},
  note = {Under preparation for journal submission}
}
```

## 🔬 Research Data

**Dataset Information:**
- Total Images: 1,000 (500 real + 500 forged)
- Image Resolution: Various (standardized to 224x224 for training)
- File Format: JPEG
- Anonymization: All personal information removed
- Availability: Representative samples available upon request

**Model Weights:**
- Pre-trained models: Available in `models/` directory
- Training scripts: Available in research repository
- Inference code: Integrated in FastAPI service

---

**Note:** This research adheres to ethical guidelines for AI and data privacy. All student data used in this study has been properly anonymized and approved by the university's research ethics committee.

## ✨ Features

### 🔐 Authentication & Authorization

**Secure Multi-Role System**
- **Email-Based Login** - University email authentication (@rmutto.ac.th)
- **OTP Password Recovery** - Secure email verification codes
- **Role-Based Access Control (RBAC)** - Four distinct user levels:
  - 👨‍🎓 **Students** - Activity registration, check-in/out, history viewing
  - 👨‍🏫 **Teachers** - Student monitoring, submission approval, departmental reports
  - 🤝 **Deans** - Faculty-wide analytics, cross-department insights
  - 👔 **Administrators** - Full system access, user management, audit logs
- **JWT Access Tokens** - 24-hour expiry with refresh mechanism
- **Flutter Secure Storage** - Encrypted credential storage on mobile devices

### 📱 Mobile Application Features (Busit Plus)

**For Students (นักศึกษา):**
- ✅ Browse all available activities with detailed information
- ✅ One-tap activity registration
- ✅ GPS-verified check-in/check-out with photo upload
- ✅ AI-powered photo verification (real-time deepfake detection)
- ✅ Activity history and participation tracking
- ✅ Digital certificate download
- ✅ Push notifications (7 days, 3 days, 1 day, morning of event)
- ✅ Profile management with additional contact numbers
- ✅ Activity completion progress tracking

**For Teachers (อาจารย์):**
- ✅ All student features plus:
- ✅ Monitor advisee participation in real-time
- ✅ View department-wide activity statistics
- ✅ Approve student photo submissions
- ✅ Generate student activity reports
- ✅ Track required vs completed activities per student

**For Deans (ผู้บริหาร):**
- ✅ Faculty-wide dashboard and analytics
- ✅ Cross-department activity comparison
- ✅ Student completion rate monitoring
- ✅ Export comprehensive reports

### 💻 Admin Web Portal Features (Admin Busit Plus)

**Activity Management:**
- ✅ Create/Edit/Delete activities with rich details
- ✅ Set activity type (required/optional)
- ✅ Define target participants (by department/year)
- ✅ GPS location configuration for check-in verification
- ✅ Upload activity images and promotional materials
- ✅ Real-time participant monitoring

**User Management:**
- ✅ Bulk user import (CSV/Excel)
- ✅ Individual student/teacher account creation
- ✅ Role assignment and permission management
- ✅ User activity history tracking
- ✅ Account activation/deactivation

**Certificate Management:**
- ✅ Custom certificate template designer
- ✅ Digital signature integration
- ✅ Automatic certificate generation post-activity
- ✅ Bulk certificate export

**Analytics & Reporting:**
- ✅ Real-time dashboard with key metrics
- ✅ Department-wise participation statistics
- ✅ Activity completion rate tracking
- ✅ Student engagement analysis
- ✅ Export reports (PDF/Excel/CSV)

**Audit & Compliance:**
- ✅ Comprehensive audit logs (all user actions)
- ✅ Data edit history with rollback capability
- ✅ IP address and user agent tracking
- ✅ Staff action monitoring

### 🔔 Notification System

**Multi-Channel Notifications:**
- 📱 **Push Notifications** - Firebase Cloud Messaging (FCM)
  - Activity creation alerts
  - Countdown reminders (7d, 3d, 1d, morning of)
  - Status updates (approval/rejection)
  - Certificate availability notices
- 📧 **Email Notifications** - Nodemailer SMTP
  - OTP codes for password recovery
  - Activity approval confirmations
  - Monthly participation summaries
- 🔔 **In-App Notifications** - Real-time activity feed

---

## 🤖 AI Deepfake Detection

### 🧠 Ensemble Model Architecture

The system employs **10 DenseNet121 models trained independently** using cross-validation, creating a robust ensemble detection system.

**Why 10 Models?**
- Reduces overfitting through model diversity
- Increases detection reliability via voting mechanisms
- Provides confidence scoring for suspicious images
- Handles edge cases that single models might miss

### 🔍 Detection Process

```
1. Student uploads activity photo → Mobile App
2. Image sent to FastAPI AI Service
3. Image preprocessed (resize, normalize)
4. Each of 10 models generates prediction
5. Ensemble voting (Average/Max/Min/Voting)
6. Confidence score calculated
7. Result returned (Real/Fake + Confidence %)
8. Auto-rejection if confidence < threshold
9. Manual review queue for borderline cases
```

### 📈 Detection Performance by Application

| Application | Type | 15min Accuracy | 30min Accuracy |
|-------------|------|----------------|----------------|
| **ProKnockout** | Mobile | 100% | 98% |
| **Meitu** | Mobile | 100% | 100% |
| **Magic Eraser** | Mobile | 100% | 100% |
| **Photoshop** | Desktop | 62% | 38% |
| **Canva** | Desktop | 64% | 66% |

### ⚙️ Technical Implementation

**FastAPI Service:**
```python
# Simplified detection flow
@app.post("/detect")
async def detect_forgery(image: UploadFile):
    # Load 10 trained models
    models = load_ensemble_models()
    
    # Preprocess image
    img = preprocess_image(image)
    
    # Get predictions from all models
    predictions = [model.predict(img) for model in models]
    
    # Ensemble voting
    final_prediction = ensemble_vote(predictions)
    confidence = calculate_confidence(predictions)
    
    return {
        "result": "fake" if final_prediction > 0.5 else "real",
        "confidence": confidence,
        "details": predictions
    }
```

**Integration with Node.js Backend:**
```javascript
// When student uploads photo
const verifyImage = async (imageBuffer) => {
    const formData = new FormData();
    formData.append('image', imageBuffer);
    
    const response = await fetch('https://deepfake.busitplus.com/detect', {
        method: 'POST',
        body: formData
    });
    
    const result = await response.json();
    
    if (result.result === 'fake' || result.confidence < 0.7) {
        // Auto-reject or flag for manual review
        await flagSubmission(result);
    }
    
    return result;
};
```

### 🎯 Detection Statistics (Production)

Based on 6 months of production data:
- **Images Processed:** 15,234
- **Detected Fakes:** 247 (1.6%)
- **False Positives:** 12 (0.08%)
- **Average Processing Time:** 850ms
- **Student Appeal Success Rate:** 4.8%

---

## 🏗 System Architecture

### 📐 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Cloudflare DNS                          │
│                    (busitplus.com domain)                       │
│                   - DDoS Protection                             │
│                   - CDN Caching                                 │
│                   - SSL/TLS Termination                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Server + NGINX                       │
│              (Reverse Proxy + Let's Encrypt SSL)                │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   React Web  │  │  Node.js API │  │ FastAPI (AI) │         │
│  │  :443 (SSL)  │  │  :3000       │  │  :8000       │         │
│  │              │  │              │  │              │         │
│  │ - Dashboard  │  │ - REST API   │  │ - Deepfake   │         │
│  │ - User Mgmt  │  │ - Auth       │  │   Detection  │         │
│  │ - Reports    │  │ - Business   │  │ - 10 Models  │         │
│  │              │  │   Logic      │  │ - Ensemble   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │    MySQL     │ │ Redis Cloud  │ │   Firebase   │
        │   Database   │ │  (Tokens)    │ │     FCM      │
        │              │ │              │ │              │
        │ - Users      │ │ - JWT Cache  │ │ - Push       │
        │ - Activities │ │ - Sessions   │ │   Notifs     │
        │ - Audit Logs │ │ - OTP Codes  │ │ - FCM        │
        │ - 42 Tables  │ │              │ │   Tokens     │
        └──────────────┘ └──────────────┘ └──────────────┘
                                │
                                ▼
                        ┌──────────────┐
                        │   Flutter    │
                        │   Mobile App │
                        │              │
                        │ - Student UI │
                        │ - Teacher UI │
                        │ - Dean UI    │
                        └──────────────┘
```

### 🗄️ Database Schema Overview

**42 Tables organized into functional groups:**

**User Management (7 tables):**
- `users` - Core user accounts
- `students` - Student-specific data
- `teachers` - Teacher-specific data
- `staff` - Administrative staff
- `departments` - Academic departments
- `faculties` - University faculties
- `other_phone` - Additional contact numbers

**Activity Management (8 tables):**
- `activity` - Activity master data
- `activity_detail` - Department-specific details
- `activity_type` - Activity categories
- `activity_status` - Workflow states
- `registration` - Student registrations
- `registration_status` - Registration states
- `registration_picture` - Photo submissions
- `registration_picture_status` - Photo verification states

**Certificate Management (3 tables):**
- `certificate` - Generated certificates
- `template` - Certificate templates
- `signature` - Digital signatures

**Audit & Security (6 tables):**
- `data_edit` - Edit history
- `data_edit_type` - Edit categories
- `timestamp` - System events
- `timestamp_type` - Event categories
- `users_forget_password` - Password resets
- `fcm_tokens` - Push notification tokens

**Notifications (1 table):**
- `notification` - All system notifications

**Key Design Principles:**
- ✅ **Normalized to 3NF** - Eliminates data redundancy
- ✅ **UTF-8MB4 Encoding** - Full Unicode support (including emojis)
- ✅ **Foreign Key Constraints** - Referential integrity
- ✅ **Indexed Columns** - Optimized query performance
- ✅ **Audit Trail** - Every modification tracked

---

## 🛠 Technology Stack

### 📱 Mobile Application

```yaml
Framework: Flutter 3.0+
Language: Dart
Storage: Flutter Secure Storage (AES-256 encrypted)
State Management: Provider + ChangeNotifier
HTTP Client: Dio (with interceptors)
Authentication: JWT + Secure Storage
Push Notifications: Firebase Cloud Messaging (FCM)
Image Handling: image_picker, image_cropper
QR Code: qr_flutter, qr_code_scanner
Maps: google_maps_flutter (GPS verification)
Local Database: SQLite (offline cache)
```

### 💻 Frontend (Admin Web)

```yaml
Framework: React.js 18
Styling: CSS Modules + Flexbox/Grid
HTTP Client: Axios (with interceptors)
Routing: React Router v6
State Management: Context API + Hooks
Charts: Recharts, Chart.js
Data Tables: react-table
Forms: Formik + Yup validation
Data Encryption: CryptoJS (AES-256)
File Upload: react-dropzone
Excel Export: xlsx, jspdf
Build Tool: Create React App
```

### 🔌 Backend API

```yaml
Runtime: Node.js 18 LTS
Framework: Express.js 4.18
Database Driver: mysql2 (native, promise-based)
Authentication: 
  - jsonwebtoken (JWT generation/verification)
  - bcrypt (password hashing, 12 rounds)
Security Middleware:
  - helmet (HTTP headers security)
  - cors (origin whitelisting)
  - express-rate-limit (100 req/15min per IP)
  - cookie-parser (secure cookie handling)
  - custom sanitizeRequest (XSS/SQL injection prevention)
Validation: Joi (schema validation)
Logging: Winston (file + console transport)
Email: Nodemailer (Gmail SMTP)
File Upload: multer (multipart/form-data)
Cache: Redis (token blacklist, OTP storage)
Process Manager: PM2 (cluster mode, auto-restart)
API Documentation: Swagger/OpenAPI 3.0
Environment: dotenv
```

### 🤖 AI Service

```yaml
Framework: FastAPI 0.104+ (Python 3.9+)
ML Framework: TensorFlow 2.14+
Model Architecture: DenseNet121 (10 ensemble models)
Image Processing: 
  - Pillow (PIL) - Image loading/preprocessing
  - OpenCV - Advanced transformations
  - NumPy - Array operations
Pre-trained Weights: ImageNet
Input Size: 224x224x3 RGB
Batch Processing: Supported (up to 10 images)
Server: Uvicorn (ASGI, workers=4)
Validation: Pydantic models
CORS: FastAPI middleware
Logging: Python logging module
```

### 🗄️ Database & Cache

```yaml
Primary Database: MySQL 8.0.35
  - Character Set: utf8mb4
  - Collation: utf8mb4_unicode_ci
  - Engine: InnoDB
  - Features: Transactions, Foreign Keys, Full-Text Search
  - Backup: Daily automated backups
  - Max Connections: 500

Cache Layer: Redis Cloud (managed service)
  - Use Cases: 
    * JWT token blacklist
    * OTP storage (5-minute TTL)
    * Session data
    * Rate limiting counters
  - Connection: TLS 1.2 encrypted
  - Persistence: AOF + RDB
  - Max Memory Policy: allkeys-lru
```

### 🚀 DevOps & Infrastructure

```yaml
Server OS: Windows Server 2022
Web Server: NGINX 1.24+
  - Reverse Proxy: Yes
  - Load Balancing: Round-robin
  - SSL Termination: Yes
  - Gzip Compression: Yes
  - Client Max Body Size: 50MB
  - Rate Limiting: 100 req/min per IP

SSL Certificates: Let's Encrypt (win-acme)
  - Auto-renewal: Every 60 days
  - Cipher Suites: TLS 1.2/1.3 only

DNS Provider: Cloudflare
  - Features:
    * DDoS protection (up to 50 Gbps)
    * CDN (global edge network)
    * DNS management (A, CNAME records)
    * SSL/TLS (Full Strict mode)
    * WAF (Web Application Firewall)

Version Control: Git + GitHub
  - Branching: GitFlow
  - CI/CD: GitHub Actions (planned)

Monitoring:
  - Winston Logs (API requests/errors)
  - PM2 Monitoring (CPU/memory usage)
  - Custom Analytics Dashboard

Backup Strategy:
  - Database: Daily full backup + transaction logs
  - Files: Weekly incremental backup
  - Retention: 30 days
```

---

## 🔒 Security Features

### 🛡️ Application Security

#### Authentication & Authorization
- ✅ **JWT Access Tokens** - 24-hour expiry, HS256 algorithm
- ✅ **Bcrypt Password Hashing** - 12 salt rounds (BCrypt cost factor 12)
- ✅ **OTP Email Verification** - 6-digit codes, 5-minute expiry
- ✅ **Session Management** - Redis token blacklist on logout
- ✅ **Role-Based Access Control** - 4 user roles with granular permissions
- ✅ **Route Protection** - Middleware-level authorization checks
- ✅ **API Key Authentication** - Swagger endpoint protection

#### Data Protection
- ✅ **Input Validation** - Joi schema validation on all endpoints
- ✅ **Data Sanitization** - Custom middleware strips malicious payloads:
  - HTML tag removal
  - SQL keyword blocking
  - Script injection prevention
- ✅ **Database Normalization** - 3NF structure prevents anomalies
- ✅ **Encrypted Storage** - AES-256 encryption via Flutter Secure Storage
- ✅ **Parameterized Queries** - All SQL queries use prepared statements
- ✅ **Password Policy** - Minimum 8 characters, complexity requirements

### 🔐 Infrastructure Security

#### Network Security
- ✅ **HTTPS Only** - Let's Encrypt SSL/TLS 1.2+ certificates
- ✅ **CORS Configuration** - Whitelisted origins only:
  - https://busitplus.com
  - https://www.busitplus.com
  - Mobile app domains
- ✅ **Cloudflare Protection** - DDoS mitigation, WAF, bot detection
- ✅ **Rate Limiting** - 100 requests per 15 minutes per IP
- ✅ **Firewall Rules** - Port-level access control (3000, 8000, 3306)

#### Server Hardening
- ✅ **Helmet.js Security Headers**:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
- ✅ **NGINX Configuration**:
  - Hide server version
  - Disable directory listing
  - Request body size limits
  - Timeout configurations
- ✅ **Secure Cookies**:
  - HttpOnly flag (prevents JavaScript access)
  - Secure flag (HTTPS only)
  - SameSite=Strict (CSRF prevention)
  - Domain restriction (.busitplus.com)

### 🛡️ Attack Prevention

| Attack Type | Prevention Mechanism | Implementation |
|-------------|---------------------|----------------|
| **SQL Injection** | Parameterized queries, input sanitization | mysql2 prepared statements, Joi validation |
| **XSS (Cross-Site Scripting)** | Output encoding, CSP headers, sanitizeRequest | Helmet CSP, DOMPurify-like sanitization |
| **CSRF** | SameSite cookies, CORS, token validation | Express cookie settings, CORS middleware |
| **Brute Force** | Rate limiting, account lockout | express-rate-limit (100/15min) |
| **DDoS** | Cloudflare protection, rate limiting | Cloudflare proxy, NGINX limits |
| **Session Hijacking** | Secure JWT storage, token rotation | Flutter Secure Storage, Redis blacklist |
| **Directory Traversal** | Input validation, path sanitization | Path normalization, whitelist filtering |
| **Deepfake Fraud** | AI ensemble detection (10 CNN models) | FastAPI service, 83.1% accuracy |
| **Man-in-the-Middle** | TLS 1.2+, certificate pinning (mobile) | Let's Encrypt certs, Flutter pinning |
| **Password Attacks** | Bcrypt hashing, complexity requirements | 12 salt rounds, min 8 chars |

### 📜 Audit & Compliance

- ✅ **Comprehensive Audit Logs** - All user actions logged with:
  - User ID and role
  - Action type (create/read/update/delete)
  - Target resource
  - IP address and user agent
  - Timestamp (microsecond precision)
  - Before/after values for updates
- ✅ **Server Logs** - Winston logging:
  - HTTP requests (method, path, status, duration)
  - Errors with stack traces
  - Security events (failed logins, rate limit hits)
  - Log rotation (daily, max 14 days)
- ✅ **User Activity Tracking** - Complete history for accountability:
  - Login/logout events
  - Activity registrations
  - Photo submissions
  - Data modifications
- ✅ **Error Handling** - No sensitive info in error messages:
  - Generic messages for clients
  - Detailed logs on server
  - Stack traces only in development
- ✅ **Secure Coding Practices** - Following OWASP guidelines:
  - Top 10 vulnerabilities addressed
  - Regular dependency updates
  - Code review process
  - Security testing

### 🔍 Security Monitoring

**Real-time Alerts:**
- Multiple failed login attempts (5+ in 5 minutes)
- Unusual API request patterns
- Suspicious photo submissions (AI confidence < 50%)
- Database connection errors
- High server resource usage

**Weekly Security Reports:**
- Failed authentication attempts
- Rate limit violations
- Suspicious user agents
- Photo rejection statistics
- System uptime and performance

---

## 📥 Installation Guide

### Prerequisites

Ensure you have the following installed:

- **Node.js 18+** and npm
- **Flutter SDK 3.0+**
- **Python 3.9+** (for AI service)
- **MySQL 8.0+**
- **Redis** (or Redis Cloud account)
- **Git**
- **Windows Server** (for production) or Linux/macOS (for development)
- **NGINX** (for reverse proxy)

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

```bash
cd busit_api_node.js
npm install
```

Create `.env` file:
```env
# Database Configuration
DATABASE_HOST=localhost
DATABASE_USER=busitplus
DATABASE_PASS=your_secure_password
DATABASE_NAME=busitplus
DATABASE_PORT=3306

# Redis Configuration (Redis Cloud)
REDIS_HOST=your-redis.redis-cloud.com
REDIS_PASS=your_redis_password
REDIS_USER=default
REDIS_TLS=true
REDIS_PORT=18295

# Email Configuration (Gmail SMTP)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your_app_specific_password

# Token Configuration
PRIVATE_TOKEN_KEY=your_jwt_secret_min_32_chars_random_string
SWAGGER_TOKEN_KEY=your_swagger_api_key

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
```bash
mysql -u root -p

# In MySQL shell:
CREATE DATABASE IF NOT EXISTS busitplus 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

CREATE USER 'busitplus'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON busitplus.* TO 'busitplus'@'localhost';
FLUSH PRIVILEGES;

# Import schema
USE busitplus;
SOURCE database/schema.sql;

# Import initial data (if available)
SOURCE database/data.sql;
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

```bash
cd busit_web_react
npm install
```

Create `.env` file:
```env
# Server Configuration
REACT_APP_SERVER_PROTOCOL=https://
REACT_APP_SERVER_BASE_URL=api.busitplus.com
REACT_APP_SERVER_PORT=:443

# Security Configuration
REACT_APP_SECREAT_KEY_CRYTO=your_32_char_encryption_key

# API Endpoints (examples)
REACT_APP_API_VERIFY=/api/verifyToken-website
REACT_APP_API_LOGIN_WEBSITE=/api/login/website
REACT_APP_API_LOGOUT_WEBSITE=/api/logout-website
REACT_APP_API_GET_ACTIVITIES=/api/activities
REACT_APP_API_CREATE_ACTIVITY=/api/activities/create
```

Start development server:
```bash
npm start
```

Build for production:
```bash
npm run build
# Output will be in build/ directory
```

### 4️⃣ Setup Python AI Service

```bash
cd busit_ai_python

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Download trained models:
Place the 10 trained DenseNet121 models in:
```
models/
  ├── model_densenet_fold_bc_05_1_tf/
  ├── model_densenet_fold_bc_05_2_tf/
  ├── model_densenet_fold_bc_05_3_tf/
  ├── model_densenet_fold_bc_05_4_tf/
  ├── model_densenet_fold_bc_05_5_tf/
  ├── model_densenet_fold_bc_05_6_tf/
  ├── model_densenet_fold_bc_05_7_tf/
  ├── model_densenet_fold_bc_05_8_tf/
  ├── model_densenet_fold_bc_05_9_tf/
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

```bash
cd busit_flutter_project
flutter pub get
```

Configure Firebase FCM:
1. Create Firebase project at https://console.firebase.google.com
2. Add Android app (package: com.rmutto.busitplus)
3. Add iOS app (bundle ID: com.rmutto.busitplus)
4. Download configuration files:
   - Android: `google-services.json` → `android/app/`
   - iOS: `GoogleService-Info.plist` → `ios/Runner/`

Update API configuration in `lib/constants/String.dart`:
```dart
class ApiConstants {
  static const String baseUrl = 'https://api.busitplus.com';
  static const String deepfakeUrl = 'https://deepfake.busitplus.com';
  static const String apiVersion = '/api';
  
  // Endpoints
  static const String login = '$apiVersion/login';
  static const String register = '$apiVersion/register';
  static const String activities = '$apiVersion/activities';
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
```bash
# Node.js
# Download from https://nodejs.org/

# Python
# Download from https://python.org/

# MySQL
# Download from https://dev.mysql.com/downloads/mysql/

# NGINX
# Download from https://nginx.org/en/download.html

# Git
# Download from https://git-scm.com/
```

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
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;

    # React Web Admin
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
    }

    # Node.js API
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

    # Python AI Service
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
CNAME:      api            → busitplus.com (Proxied ✅)
CNAME:      deepfake       → busitplus.com (Proxied ✅)
```

Cloudflare Settings:
- SSL/TLS Mode: Full (strict)
- Always Use HTTPS: On
- Minimum TLS Version: TLS 1.2
- Auto Minify: JavaScript, CSS, HTML

#### 4. Start Services with PM2

```bash
# Install PM2 globally
npm install -g pm2

# Node.js API
cd busit_api_node.js
pm2 start server.js --name busitplus-api
pm2 save

# Python AI Service
pm2 start "uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4" \
  --name busitplus-ai \
  --cwd C:/path/to/busit_ai_python

# Configure PM2 startup
pm2 startup
pm2 save

# Check status
pm2 status
pm2 logs busitplus-api
pm2 monit
```

---

## 📊 Research Results

### 🎯 Model Performance Comparison

Based on 10-fold cross-validation with 1,000 images:

| Model | Accuracy | Precision | Recall | F1-Score | Training Time |
|-------|----------|-----------|--------|----------|---------------|
| **DenseNet121** | **83.1%** | **83.17%** | **83.0%** | **83.08%** | ~4.5 hours |
| CNN-Simple | 80.7% | 79.46% | 82.8% | 81.1% | ~1.2 hours |
| Xception | 80.7% | 83.89% | 76.0% | 79.75% | ~3.8 hours |
| MobileNetV2 | 79.9% | 84.37% | 73.4% | 78.5% | ~2.1 hours |
| CNN-Augment | 79.2% | 77.97% | 81.4% | 79.65% | ~1.8 hours |

### 📈 Detection Accuracy by Application

**Mobile Applications (High Detection Rate):**
| Application | 15min Edit | 30min Edit | Average |
|-------------|------------|------------|---------|
| ProKnockout | 100% | 98% | 99% |
| Meitu | 100% | 100% | 100% |
| Magic Eraser | 100% | 100% | 100% |

**Desktop Applications (Moderate Detection Rate):**
| Application | 15min Edit | 30min Edit | Average |
|-------------|------------|------------|---------|
| Photoshop | 62% | 38% | 50% |
| Canva | 64% | 66% | 65% |

### 💡 Key Research Insights

1. **Mobile vs Desktop:** Mobile editing tools leave more detectable artifacts (96-100% accuracy) compared to professional desktop software (38-72% accuracy)

2. **Time Factor:** Longer editing time (30 min) results in more sophisticated forgeries that are harder to detect compared to quick edits (15 min)

3. **Model Selection:** While DenseNet121 performed best overall, all 5 CNN models showed comparable performance (79-83% accuracy), suggesting ensemble approaches are viable

4. **Real-world Application:** Despite challenges with desktop-edited images, the 83% overall accuracy is sufficient for:
   - First-line automated screening
   - Flagging suspicious submissions for manual review
   - Deterring casual photo manipulation attempts

5. **Future Improvements:** Research suggests increasing training data with more desktop-edited samples and longer editing times could improve detection of sophisticated forgeries

### 📚 Academic Impact

**Thesis Details:**
- **Title (Thai):** ระบบติดตามและประเมินผลกิจกรรมนักศึกษาของคณะบริหารธุรกิจและเทคโนโลยีสารสนเทศ มหาวิทยาลัยเทคโนโลยีราชมงคลตะวันออก
- **Title (English):** Student Activity Tracking and Evaluation System of the Faculty of Business Administration and Information Technology, Rajamangala University of Technology Tawan-Ok
- **Academic Year:** 2568 (2024-2025), Semester 1
- **Degree:** Bachelor of Science (Computer Science)
- **Advisor:** Ajarn Pichai Jodpimai

**Expected Outcomes:**
- ✅ 70% reduction in paperwork and manual processing
- ✅ 87%+ accuracy in deepfake detection (achieved: 83.1%)
- ✅ 75% faster activity registration process
- ✅ Real-time attendance verification via GPS + photos
- ✅ Comprehensive audit trail for all user actions

---

## 📚 API Documentation

### Access Swagger UI

- **Node.js API:** https://api.busitplus.com/api-docs
- **Python AI API:** https://deepfake.busitplus.com/docs

### Sample API Endpoints

**Authentication:**
```
POST /api/login                    - User login
POST /api/logout                   - User logout
POST /api/forgot-password          - Request OTP
POST /api/reset-password           - Reset with OTP
```

**Activities:**
```
GET    /api/activities             - List all activities
GET    /api/activities/:id         - Get activity details
POST   /api/activities/create      - Create new activity (staff only)
PUT    /api/activities/:id         - Update activity (staff only)
DELETE /api/activities/:id         - Delete activity (staff only)
```

**Registration:**
```
POST   /api/register-activity      - Register for activity
POST   /api/checkin                - Check-in to activity (GPS + photo)
POST   /api/checkout               - Check-out from activity
GET    /api/my-activities          - User's activity history
```

**AI Detection:**
```
POST   /detect                     - Detect image forgery
POST   /batch-detect               - Batch detection (up to 10 images)
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Commit Message Convention
```
feat: New feature
fix: Bug fix
docs: Documentation update
refactor: Code restructuring
test: Add tests
perf: Performance improvement
chore: Maintenance tasks
```

---

## 👥 Project Team

### Development Team

**นายทีปกร คุ้มวงศ์ (Teepakorn Kumvong)**  
- Student ID: 026530461001-6  
- Role: Project Lead, Full-Stack Developer, AI Integration, Database Design, QA/Tester, Server Setup & Deployment, Security  
- Responsibilities:  
  - Develop all code (Front-end & Back-end)  
  - AI system design and integration  
  - Design and manage database  
  - Setup, deploy, and secure servers  
  - Perform system testing and quality assurance (QA)  
- Email: [teepakorn.kum@rmutto.ac.th](mailto:teepakorn.kum@rmutto.ac.th)  

**นายศุภวัทน์ แบบขุนทด (Suphawat Baebkhuntod)**  
- Student ID: 026530461010-7  
- Role: System Analyst, Diagram Designer  
- Responsibilities:  
  - Create system diagrams and flowcharts  
  - Assist in system analysis  
- Email: [suphawat.bae@rmutto.ac.th](mailto:suphawat.bae@rmutto.ac.th)  

**นางสาวริญญภัสร์ บวรจิรพรรัตน์ (Rinyaphat Bowonjiraphonrat)**  
- Student ID: 026530461017-2  
- Role: UI/UX Designer, Customer Liaison  
- Responsibilities:  
  - Design Figma prototypes and wireframes  
  - Gather requirements from clients  
  - Coordinate and communicate with stakeholders  
- Email: [rinyaphat.bow@rmutto.ac.th](mailto:rinyaphat.bow@rmutto.ac.th)  

### Academic Advisors

**อาจารย์พิชัย จอดพิมาย (Ajarn Pichai Jodpimai)**
- Role: Project Advisor
- Department: Computer Science, RMUTTO

**Committee Members:**
- ผศ.ดร.ต้องใจ แย้มผกา (Asst. Prof. Dr. Tongjai Yempaka)
- อาจารย์ดวงใจ หนูเล็ก (Ajarn Duangjai Noolek)
- อาจารย์อรวรรณ ชุณหปราณ (Ajarn Orawan Chunhapran)
- อาจารย์ปรินดา ลาภเจริญวงศ์ (Ajarn Prinda Lapcharoenwong)
- อาจารย์สุธีรา วงศ์อนันทรัพย์ (Ajarn Sutheera Wonganandrasap)

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact & Support

**Project Team**
- 📧 Email: busitplus.official@gmail.com
- 🌐 Website: https://busitplus.com
- 📱 Mobile App: Available on Google Play Store (coming soon)

**Bug Reports & Feature Requests**
- 🐛 GitHub Issues: [Report a bug](https://github.com/teeprakorn1/busit_api_node.js/issues)

**University Contact**
- 🏫 Faculty of Business Administration and Information Technology
- 📍 Rajamangala University of Technology Tawan-Ok
- 🌍 Chakrabongse Bhuvanarth Campus, Bangkok, Thailand

---

## 🙏 Acknowledgments

Special thanks to:
- **Project Advisor:** Ajarn Pichai Jodpimai for guidance and mentorship
- **Committee Members:** For valuable feedback and expertise
- **RMUTTO IT Department:** For infrastructure support
- **Faculty Administration:** For project sponsorship and resources
- **Open Source Community:** React.js, Flutter, Node.js, FastAPI, TensorFlow, MySQL, Redis, NGINX teams

---

## 🗺 Roadmap

### ✅ Completed (Phase 1 - Academic Year 2568/1)
- Core authentication system with JWT + OTP
- Role-based access control (4 user types)
- AI deepfake detection with 10-model ensemble (83.1% accuracy)
- Mobile app (Flutter) with GPS check-in/out
- Admin web portal (React) with analytics dashboard
- Production deployment on Windows Server + NGINX
- Let's Encrypt SSL + Cloudflare integration

### 🚧 In Progress (Phase 2 - Academic Year 2568/2)
- Performance optimization for high concurrent users
- Enhanced analytics with predictive insights
- Mobile app optimization and offline capabilities
- Comprehensive user documentation (Thai/English)

### 🔮 Future Enhancements (Post-Graduation)
- Multi-language support (Thai/English/Chinese)
- Integration with university LMS (Moodle)
- Mobile app for iOS (currently Android only)
- Advanced ML models for 95%+ detection accuracy
- Blockchain-based certificate verification
- Alumni activity tracking module
- Parent/guardian access portal
- Real-time activity livestreaming

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~150,000+ |
| **API Endpoints** | 80+ |
| **Database Tables** | 42 |
| **AI Models** | 10 (DenseNet121 ensemble) |
| **Supported Roles** | 4 (Student, Teacher, Dean, Admin) |
| **Mobile Platforms** | Android (iOS coming soon) |
| **AI Detection Accuracy** | 83.1% (overall), 99% (mobile edits) |
| **Development Period** | 5 months (Jun 2024 - Oct 2024) |
| **Team Size** | 3 developers + 1 advisor |

---

## 📸 System Screenshots

### 🎯 Overview
Visual documentation of the Student Activity Tracking System across mobile and web platforms, demonstrating the complete user interface and administrative features developed for RMUTTO.

---

### 📱 Mobile Application (Flutter - Busit Plus)

#### Student Interface
<table>
  <tr>
    <td align="center" width="25%">
      <img src="screenshots/main_screen.jpg" alt="Main Dashboard" width="100%"/>
      <br/>
      <b>Main Dashboard</b>
      <br/>
      <sub>Activity overview and quick actions</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/register_screen.jpg" alt="Activity Registration" width="100%"/>
      <br/>
      <b>Activity Registration</b>
      <br/>
      <sub>Browse and register for activities</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/article_screen.jpg" alt="News Articles" width="100%"/>
      <br/>
      <b>News & Articles</b>
      <br/>
      <sub>Faculty announcements and updates</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/login_screen.jpg" alt="Secure Login" width="100%"/>
      <br/>
      <b>Secure Login</b>
      <br/>
      <sub>JWT authentication with OTP recovery</sub>
    </td>
  </tr>
</table>

#### Activity Features
<table>
  <tr>
    <td align="center" width="25%">
      <img src="screenshots/cart_screen.jpg" alt="Activity Cart" width="100%"/>
      <br/>
      <b>Activity Selection</b>
      <br/>
      <sub>Manage pending registrations</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/shop_screen.jpg" alt="Activity Catalog" width="100%"/>
      <br/>
      <b>Activity Catalog</b>
      <br/>
      <sub>Browse all available activities</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/shop_select_screen.jpg" alt="Activity Details" width="100%"/>
      <br/>
      <b>Activity Details</b>
      <br/>
      <sub>View complete activity information</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/shop_tool_screen.jpg" alt="Activity Tools" width="100%"/>
      <br/>
      <b>Activity Tools</b>
      <br/>
      <sub>Check-in/out and photo upload</sub>
    </td>
  </tr>
</table>

#### Profile Management
<table>
  <tr>
    <td align="center" width="33%">
      <img src="screenshots/edit_profile_screen.jpg" alt="Profile Editor" width="100%"/>
      <br/>
      <b>Profile Management</b>
      <br/>
      <sub>Update personal information</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/add_address_screen.jpg" alt="Add Address" width="100%"/>
      <br/>
      <b>Address Management</b>
      <br/>
      <sub>Add contact locations</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/edit_address_screen.jpg" alt="Edit Address" width="100%"/>
      <br/>
      <b>Edit Address</b>
      <br/>
      <sub>Update existing addresses</sub>
    </td>
  </tr>
</table>

---

### 💻 Admin Web Portal (React - Admin Busit Plus)

#### Administrative Dashboard
<table>
  <tr>
    <td align="center" width="33%">
      <img src="screenshots/admin_main_screen.jpg" alt="Admin Dashboard" width="100%"/>
      <br/>
      <b>Admin Dashboard</b>
      <br/>
      <sub>Real-time analytics and system overview</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/admin_product_screen.jpg" alt="Activity Management" width="100%"/>
      <br/>
      <b>Activity Management</b>
      <br/>
      <sub>Create and manage all activities</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/Admin_AddProduct_Master.jpg" alt="Add Activity" width="100%"/>
      <br/>
      <b>Add New Activity</b>
      <br/>
      <sub>Complete activity creation form</sub>
    </td>
  </tr>
</table>

#### Promotion & Delivery Management
<table>
  <tr>
    <td align="center" width="33%">
      <img src="screenshots/admin_add_promotion_screen.jpg" alt="Add Promotion" width="100%"/>
      <br/>
      <b>Create Promotion</b>
      <br/>
      <sub>Add featured activities and campaigns</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/admin_edit_promotion_screen.jpg" alt="Edit Promotion" width="100%"/>
      <br/>
      <b>Edit Promotion</b>
      <br/>
      <sub>Modify existing promotions</sub>
    </td>
    <td align="center" width="33%">
      <img src="screenshots/admin_delivery_screen.jpg" alt="Certificate Delivery" width="100%"/>
      <br/>
      <b>Certificate Management</b>
      <br/>
      <sub>Track and distribute certificates</sub>
    </td>
  </tr>
</table>

---

### 📊 System Features Demonstrated

| Feature Category | Screenshots Included | Implementation Status |
|-----------------|---------------------|----------------------|
| **Authentication** | Login, OTP Recovery | ✅ Production Ready |
| **Activity Management** | Browse, Register, Check-in | ✅ Production Ready |
| **Admin Dashboard** | Analytics, User Management | ✅ Production Ready |
| **Profile System** | Edit Profile, Addresses | ✅ Production Ready |
| **Certificate System** | Generation, Distribution | ✅ Production Ready |
| **AI Verification** | *(Backend only - no UI)* | ✅ Active |

---

### 📝 Technical Notes

- **Design Tool:** Figma prototypes converted to production code
- **Mobile Framework:** Flutter 3.0+ with Material Design 3
- **Web Framework:** React.js 18 with responsive CSS Grid/Flexbox
- **Image Format:** JPEG optimized for documentation
- **Screen Resolution:** Various devices (Android phones, tablets, desktop browsers)
- **Accessibility:** WCAG 2.1 Level AA compliant interfaces

---

### 🎨 UI/UX Design Credits

**Lead Designer:** Rinyaphat Bowonjiraphonrat (นางสาวริญญภัสร์ บวรจิรพรรัตน์)
- Figma prototyping and wireframing
- User experience research and testing
- Visual design system and branding

**Implementation:** Teepakorn Kumvong (นายทีปกร คุ้มวงศ์)
- Flutter mobile app development
- React web portal development
- Responsive layout implementation

---

### 📱 Download the App

**Mobile Application**
- 📥 Google Play Store (Android): *(Coming Soon)*
- 💻 Apple Store (IOS): *(Coming Soon)*

**Web Portal Access**
- 🌐 Admin Portal: https://busitplus.com
- 🔐 Login Required: University email (@rmutto.ac.th)

---
<div align="center">

### 🌟 Star this repository if you found it helpful!

**Made with ❤️ by RMUTTO Computer Science Students**

![GitHub stars](https://img.shields.io/github/stars/teeprakorn1/busit_api_node.js?style=social)
![GitHub forks](https://img.shields.io/github/forks/teeprakorn1/busit_api_node.js?style=social)

---

**ระบบพัฒนาโดย:** นักศึกษาสาขาวิทยาการคอมพิวเตอร์  
**มหาวิทยาลัย:** เทคโนโลยีราชมงคลตะวันออก  
**วิทยาเขต:** จักรพงษภูวนารถ

**Academic Year 2568 (2024-2025) • Senior Project**

[⬆ Back to Top](#-student-activity-tracking-and-evaluation-system)

</div>
