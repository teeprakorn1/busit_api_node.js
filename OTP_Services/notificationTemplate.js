function notificationEmailTemplate(email, {
  heading = "แจ้งเตือนจากระบบ",
  subheading = "คุณได้รับอีเมลฉบับนี้จาก BusitPlus",
  message = "นี่คืออีเมลสำหรับการทดสอบระบบ"
} = {}) {
  const logoURL = "https://drive.google.com/uc?export=view&id=1Xj2BWf7bdQzR_SBRNSNtYM2_YFnPfFeL";

  const safeMessage = message && message.trim()
    ? `<p>${message}</p>`
    : `<p>นี่คืออีเมลสำหรับการทดสอบระบบ</p>`;

  return `
  <!DOCTYPE html>
  <html lang="th">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${heading}</title>
      <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
      <style>
        body {
          margin: 0;
          padding: 0;
          background-color: #f9fbfc;
          font-family: 'Roboto', sans-serif;
        }
        .container {
          max-width: 520px;
          margin: 40px auto;
          background-color: #ffffff;
          padding: 36px 32px;
          border-radius: 16px;
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
        }
        .logo {
          text-align: center;
          margin-bottom: 24px;
        }
        .logo img {
          width: 72px;
          height: 72px;
          border-radius: 50%;
        }
        .heading {
          text-align: center;
          color: #1a202c;
          font-size: 22px;
          font-weight: 600;
          margin-bottom: 6px;
        }
        .subheading {
          text-align: center;
          color: #718096;
          font-size: 14px;
          margin-bottom: 30px;
        }
        .content {
          color: #2d3748;
          font-size: 16px;
          line-height: 1.6;
          text-align: center;
        }
        .note {
          text-align: center;
          font-size: 13px;
          color: #718096;
          margin-top: 20px;
        }
        .divider {
          border-top: 1px solid #e2e8f0;
          margin: 36px 0 24px;
        }
        .footer {
          font-size: 12px;
          color: #a0aec0;
          text-align: center;
        }
        @media only screen and (max-width: 600px) {
          .container {
            padding: 24px 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <!-- Logo -->
        <div class="logo">
          <img src="${logoURL}" alt="Logo" />
        </div>

        <!-- Heading -->
        <div class="heading">${heading}</div>
        <div class="subheading">${subheading}</div>

        <!-- Content -->
        <div class="content">
          <p>สวัสดีคุณ <strong>${email}</strong>,</p>
          ${safeMessage}
          <p>นี่คืออีเมลแจ้งเตือนจากระบบของเรา หากคุณมีข้อสงสัยกรุณาติดต่อฝ่ายสนับสนุน</p>
        </div>

        <!-- Notes -->
        <div class="note">
          ขอบคุณที่ใช้บริการของเรา
        </div>

        <div class="divider"></div>

        <!-- Footer -->
        <div class="footer">
          © 2025 BusitPlus. All rights reserved.
        </div>
      </div>
    </body>
  </html>
  `;
}

module.exports = notificationEmailTemplate;
