# 🧑‍⚕️ Student Activity Tracking and Evaluation System of the Faculty of Business Administration and Information Technology, Rajamangala University of Technology Tawan-Ok.

**Student Activity Tracking and Evaluation System** is a web app for **managing patients, profiles, doctors, and appointments**.  
It uses **React** for the frontend and **Node.js/Express** for the backend API with **MySQL database**, **JWT authentication**, and **Swagger API documentation**.  

The backend also includes **Winston logging**, **Helmet security headers**, **cookie parsing**, and **request sanitization** for better security.  

The app can be deployed on **Windows Server** with **NGINX reverse proxy**, **Let’s Encrypt SSL**, and **Cloudflare DNS**.  

---

## 🚀 Key Features

- 🔑 **Authentication & Authorization** – JWT token, user registration, login/logout  
- 👤 **Patient Profile** – View and update personal info, medical history  
- 👨‍⚕️ **Doctor Search** – Search by name or specialization  
- 📅 **Appointment Management** – Book and check doctor schedules  
- 📊 **Swagger Documentation** – Easy API testing and documentation  
- 🛡️ **Security** – Helmet, sanitizeRequest, rate limiter, cookie parser  
- 📜 **Server Logging** – Request and error logging with Winston  
- 🌐 **Deployment Ready** – Supports Windows Server + NGINX + HTTPS + Cloudflare  

---

## ⚙️ System Architecture

| Component                  | Description |
|----------------------------|-------------|
| **📱 React Frontend**       | SPA using React Components + CSS Modules |
| **🌐 Node.js Backend**      | RESTful API, JWT Auth, Swagger, Logging, Security Middleware |
| **💾 MySQL Database**       | Stores users, doctors, appointments, patient history |
| **🔧 Deployment Layer**     | Windows Server + NGINX Reverse Proxy + Let’s Encrypt SSL + Cloudflare DNS |

> Frontend and Backend are separate but communicate via REST APIs  

---

## 🧰 Tech Stack

### 💻 Frontend

- React + JavaScript  
- React Components + CSS Modules  
- Axios for API requests  
- React Router for navigation  
- Responsive design for desktop and mobile  

### 🌐 Backend (API)

- Node.js + Express  
- RESTful APIs: `/api/register`, `/api/login`, `/api/patient/*`, `/api/doctor/*`, `/api/appointment/*`  
- **Swagger** for API documentation  
- **Security Middleware**:
  - **Helmet** – Set secure HTTP headers  
  - **cookie-parser** – Parse and manage cookies  
  - **sanitizeRequest** – Prevent SQL/NoSQL injection and malicious payloads  
  - **express-rate-limit** – Protect against brute-force attacks  
- **Logging**: Winston for request and error logs  
- **MySQL Database**  
- **JWT & bcrypt** for authentication
  
### 🧰 Deployment & DevOps

- **Windows Server**  
- **NGINX Reverse Proxy**  
  - doctor.busitplus.com → React Frontend  
  - docapi.busitplus.com → Node.js API  
- **SSL / HTTPS** – Let’s Encrypt  
- **DNS** – Cloudflare  

### 🧪 Testing & Tools

- **Postman** – For testing all API endpoints efficiently.
- **Visual Studio Code** – Primary IDE for frontend and backend development.
- **MySQL Workbench** – For managing and querying the database.
- **Git & GitHub** – Version control and collaboration.
- **Swagger UI** – To explore and test RESTful APIs via interactive documentation.
- **Winston** – Logging server requests and errors.
- **cookie-parser** – For handling cookies in Express.js.
- **helmet** – Adds security headers to HTTP responses.
- **sanitizeRequest** – Sanitizes incoming requests to prevent injection attacks.

---

## 🛠️ Installation Guide

Follow these steps to set up the project locally or on your server.

### 1️⃣ Clone the Repositories

```bash
# Clone Frontend (React)
git clone https://github.com/teeprakorn1/busit_web_react.git
cd busitplus_react

# Clone Frontend (Flutter Application)
git clone https://github.com/teeprakorn1/busit_flutter_project.git
cd busitplus_flutter

# Clone Backend (Node.js API)
git clone https://github.com/teeprakorn1/busit_api_node.js.git
cd busitplus_nodejs

# Clone Backend (Python API)
git clone https://github.com/teeprakorn1/busit_ai_python.git
cd busitplus_python_ai
```

### 2️⃣ Setup Backend (Node.js API)
#### Navigate to the backend folder:
```bash
cd busitplus_nodejs
```
#### Install dependencies:
```bash
npm install
```
#### Create a .env file in the root of the backend:
```env
# Database Configuration
DATABASE_HOST=db.busitplus.com
DATABASE_USER=busitplus
DATABASE_PASS=YOUR_DATA_KEY
DATABASE_NAME=busitplus
DATABASE_PORT=3306

# Redis Configuration
REDIS_HOST=redis-18295.c1.ap-southeast-1-1.ec2.redns.redis-cloud.com
REDIS_PASS=YOUR_DATA_KEY
REDIS_USER=default
REDIS_TLS=true

# Email Configuration
EMAIL_USER=busitplus.official@gmail.com
EMAIL_PASS=YOUR_DATA_KEY

# Token Configuration
PRIVATE_TOKEN_KEY=busitplus_rmutto_generate_YOUR_DATA_KEY
SWAGGER_TOKEN_KEY=busitplus_rmutto_generate_YOUR_DATA_KEY

# Client URL
WEB_CLIENT_URL_DEV=http://localhost:3001
WEB_CLIENT_URL_PROD=https://busitplus.com
WEB_CLIENT_URL_PROD_2=https://www.busitplus.com
COOKIE_DOMAIN_PROD=.busitplus.com

# Server Ports
SERVER_PORT=3000
REDIS_PORT=18295

# Server Configuration
# Environment Mode (0: Development, 1: Production)
ENV_MODE=1
```
#### Run database migrations / create tables manually in MySQL:
```sql
CREATE DATABASE IF NOT EXISTS busitplus CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
#### Start the backend server:
```bash
pm2 start server.js --name busitplus-api-server
```
### 3️⃣ Setup Frontend (React)
#### Navigate to the frontend folder:
```bash
cd busitplus_react
```
#### Install dependencies:
```bash
npm install
```
#### Create a .env file in the frontend root:
```env
#Server Configuration
REACT_APP_SERVER_PROTOCOL=https://
REACT_APP_SERVER_BASE_URL=api.busitplus.com
REACT_APP_SERVER_PORT=:443

#Security Configuration
REACT_APP_SECREAT_KEY_CRYTO=PRIVATE_TOKEN_KEY_busitplus_rmutto_generate_YOUR_DATA_KEY

#API Configuration
REACT_APP_API_VERIFY=/api/verifyToken-website
REACT_APP_API_LOGIN_WEBSITE=/api/login/website
REACT_APP_API_LOGOUT_WEBSITE=/api/logout-website
REACT_APP_API_ADMIN_GET_WEBSITE=/api/admin/data/get
REACT_APP_API_TIMESTAMP_WEBSITE_INSERT=/api/timestamp/website/insert
REACT_APP_API_TIMESTAMP_WEBSITE_GET=/api/timestamp/get
REACT_APP_API_TIMESTAMP_WEBSITE_GET_ID=/api/timestamp/get/users/
REACT_APP_API_ADMIN_FACULTIES_GET=/api/admin/faculties/
REACT_APP_API_ADMIN_DEPARTMENTS_GET=/api/admin/departments/
REACT_APP_API_ADMIN_DEPARTMENTS_STATS_ALL=/api/admin/departments/stats/all
REACT_APP_API_ADMIN_DEPARTMENTS=/departments
REACT_APP_API_ADMIN_TEACHERS=/teachers
REACT_APP_API_ADMIN_STUDENT_ADD=/api/admin/users/student/add
REACT_APP_API_ADMIN_TEACHER_ADD=/api/admin/users/teacher/add
REACT_APP_API_ADMIN_STUDENT_ADD_BULK=/api/admin/users/student/import
REACT_APP_API_ADMIN_TEACHER_ADD_BULK=/api/admin/users/teacher/import
REACT_APP_API_TIMESTAMP_SEARCH=/api/timestamp/search?
REACT_APP_API_ADMIN_STUDENTS_GET=/api/admin/students
REACT_APP_API_ADMIN_STATUS=/status
REACT_APP_API_ADMIN_TEACHERS_GET=/api/admin/teachers
REACT_APP_API_ADMIN_IMAGES_GET=/api/images/profile-images-admin/
REACT_APP_API_ADMIN_IMAGES_CERTIFICATE_GET=/api/images/certificate-files/
REACT_APP_API_USERS_DETAIL=/api/admin/users
REACT_APP_API_DATAEDIT_GET=/api/dataedit/get
REACT_APP_API_DATAEDIT_SEARCH=/api/dataedit/search
REACT_APP_API_DATAEDIT_INSERT=/api/dataedit/website/insert
REACT_APP_API_STAFF_SEARCH=/api/staff/search
REACT_APP_API_TEMPLATES_GET=/api/admin/templates
REACT_APP_API_ACTIVITIES_GET=/api/admin/activities
REACT_APP_API_ACTIVITY_TYPES_GET=/api/admin/activity-types
REACT_APP_API_ACTIVITY_STATUSES_GET=/api/admin/activity-statuses
REACT_APP_API_TEMPLATES_GET=/api/admin/templates
REACT_APP_API_IMAGES_ACTIVITY_GET=/api/images/activity-files
REACT_APP_API_ADMIN_ACTIVITY_TYPES_GET=/api/admin/activity-types
REACT_APP_API_ADMIN_ACTIVITY_STATUSES_GET=/api/admin/activity-statuses
REACT_APP_API_ADMIN_IMAGES_ACTIVITY=/api/admin/images/activity/
```
#### Start the frontend app:
```bash
npm start
```
React app will run on → http://localhost:3000
### 4️⃣ Access Swagger API Docs
#### Once the backend is running, open:
```bash
http://localhost:3000/api-docs
```
### 5️⃣ Deployment (Windows Server + NGINX + Cloudflare + SSL)
#### Build React for production
```bash
cd busitplus_react
npm run build
```
#### Configure NGINX reverse proxy
Example configuration:
```nginx
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;
    client_max_body_size 10M;

    # ==========================
    # Default server
    # ==========================
    server {
        listen 80 default_server;
        listen 443 ssl default_server;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        return 444;
    }

    # ==========================
    # React Web Server (busitplus.com)
    # ==========================
    server {
        listen 80;
        server_name busitplus.com www.busitplus.com;

        location /.well-known/acme-challenge/ {
            root C:/nginx/html;
            try_files $uri =404;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name busitplus.com www.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        root C:/nginx/react-build;
        index index.html index.htm;

        location / {
            try_files $uri $uri/ /index.html;
        }
    }

    # ==========================
    # Node.js API Server (api.busitplus.com, port 3000)
    # ==========================
    server {
        listen 80;
        server_name api.busitplus.com;

        location /.well-known/acme-challenge/ {
            root C:/nginx/html;
            try_files $uri =404;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name api.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://localhost:3000;
            proxy_http_version 1.1;

            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;

            proxy_cache_bypass $http_upgrade;
        }
    }

	  # ==========================
    # FastAPI Deepfake Detection (deepfake.busitplus.com, port 8000)
    # ==========================
    server {
        listen 80;
        server_name deepfake.busitplus.com;

        location /.well-known/acme-challenge/ {
            root C:/nginx/html;
            try_files $uri =404;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name deepfake.busitplus.com;

        ssl_certificate      C:/nginx/certs/busitplus.com-crt.pem;
        ssl_certificate_key  C:/nginx/certs/busitplus.com-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
        send_timeout 300;

        location / {
            proxy_pass http://localhost:8000;
            proxy_http_version 1.1;

            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;

            proxy_cache_bypass $http_upgrade;
        }
    }
}
```
#### Enable SSL with Let’s Encrypt
```bash
sudo certbot --nginx -d busitplus.com -d api.busitplus.com -d deepfake.busitplus.com
```
#### Point DNS to server via Cloudflare
---
Done! Now you can access:
- Frontend → https://busitplus.com  
- Backend API → https://api.busitplus.com  
- Node.js API Docs (Swagger) → https://api.busitplus.com/api-docs
- Python API Docs (Swagger) → https://deepfake.busitplus.com/api-docs
