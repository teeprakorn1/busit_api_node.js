function otpEmailTemplate(email, otp , message) {
  const logoURL = "https://drive.google.com/uc?export=view&id=1Xj2BWf7bdQzR_SBRNSNtYM2_YFnPfFeL";
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  const formatter = new Intl.DateTimeFormat('th-TH', {
    dateStyle: 'long',
    timeStyle: 'short',
    timeZone: 'Asia/Bangkok'
  });
  const formattedExpire = formatter.format(expiresAt);

  return `
  <!DOCTYPE html>
  <html lang="th">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>OTP Verification</title>
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
        }
        .otp-box {
          text-align: center;
          margin: 32px 0;
        }
        .otp {
          display: inline-block;
          font-size: 38px;
          font-weight: bold;
          background-color: #edf2f7;
          color: #2b6cb0;
          padding: 14px 24px;
          border-radius: 12px;
          letter-spacing: 4px;
        }
        .expire {
          color: #e53e3e;
          font-weight: 500;
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
          .otp {
            font-size: 28px;
            padding: 10px 16px;
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
        <div class="heading">ยืนยันรหัส OTP ของคุณ</div>
        <div class="subheading">เพื่อความปลอดภัยของบัญชี</div>

        <!-- Content -->
        <div class="content">
          <p>สวัสดีคุณ <strong>${email}</strong>,</p>
          <p>มีการ${message} มายังบัญชีของคุณ กรุณาใช้รหัส OTP ด้านล่างเพื่อยืนยันตัวตนของคุณ:</p>
        </div>

        <!-- OTP Display -->
        <div class="otp-box">
          <div class="otp">${otp}</div>
        </div>

        <!-- Expire Time -->
        <div class="content">
          <p><span class="expire">รหัสนี้จะหมดอายุภายในวันที่ ${formattedExpire}</span></p>
        </div>

        <!-- Notes -->
        <div class="note">
          ** อย่าเปิดเผยรหัส OTP กับผู้อื่น **<br />
          เพื่อความปลอดภัยของบัญชีคุณ รหัส OTP เป็นข้อมูลส่วนบุคคลที่ไม่ควรเปิดเผยข้อมูลต่อผู้ใด
        </div>

        <div class="divider"></div>

        <!-- Footer -->
        <div class="footer">
          หากคุณไม่ได้ร้องขอรหัส OTP นี้<br />
          โปรดละเว้นอีเมลนี้ และไม่ต้องดำเนินการใด ๆ<br />
          © 2025 BusitPlus. All rights reserved.
        </div>
      </div>
    </body>
  </html>
  `;
}

module.exports = otpEmailTemplate;
