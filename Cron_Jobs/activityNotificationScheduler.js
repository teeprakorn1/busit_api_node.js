const cron = require('node-cron');
const db = require('../Server_Services/databaseClient');
const { sendNotificationToMultipleUsers, saveNotificationForUsers } = require('../FCM_Services/notificationService');

// ===================== HELPER FUNCTIONS =====================

/**
 * ดึงรายชื่อผู้ใช้ที่มีสิทธิ์เข้าร่วมกิจกรรม
 * @param {number} activityId - Activity ID
 * @returns {Promise<Array>} - Array of user IDs
 */
const getEligibleUsersForActivity = (activityId) => {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT DISTINCT u.Users_ID
      FROM users u
      LEFT JOIN student s ON u.Users_ID = s.Users_ID
      LEFT JOIN teacher t ON u.Users_ID = t.Users_ID
      WHERE u.Users_IsActive = TRUE
      AND (
        (u.Users_Type = 'student' 
         AND s.Student_IsGraduated = FALSE 
         AND s.Department_ID IN (
            SELECT ad.Department_ID 
            FROM activitydetail ad 
            WHERE ad.ActivityDetail_ID = ?
         ))
        OR 
        (u.Users_Type = 'teacher' 
         AND t.Teacher_IsResign = FALSE 
         AND EXISTS (
            SELECT 1 
            FROM activity a 
            WHERE a.Activity_ID = ? 
            AND a.Activity_AllowTeachers = TRUE
         ))
      )
    `;
    
    db.query(sql, [activityId, activityId], (err, results) => {
      if (err) {
        console.error('Error fetching eligible users:', err);
        return reject(err);
      }
      resolve(results.map(r => r.Users_ID));
    });
  });
};

/**
 * ดึงรายชื่อผู้ใช้ที่ลงทะเบียนกิจกรรมแล้ว
 * @param {number} activityId - Activity ID
 * @returns {Promise<Array>} - Array of user IDs
 */
const getRegisteredUsersForActivity = (activityId) => {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT DISTINCT r.Users_ID 
      FROM registration r 
      WHERE r.Activity_ID = ?
      AND r.RegistrationStatus_ID IN (
        SELECT RegistrationStatus_ID 
        FROM registrationstatus 
        WHERE RegistrationStatus_Name IN ('ลงทะเบียนสำเร็จ', 'รอยืนยัน', 'เข้าร่วมสำเร็จ')
      )
    `;
    
    db.query(sql, [activityId], (err, results) => {
      if (err) {
        console.error('Error fetching registered users:', err);
        return reject(err);
      }
      resolve(results.map(r => r.Users_ID));
    });
  });
};

/**
 * ตรวจสอบว่าแจ้งเตือนไปแล้วหรือยัง (ปรับปรุงให้แม่นยำขึ้น)
 * @param {number} activityId - Activity ID
 * @param {string} notificationType - Notification type
 * @returns {Promise<boolean>}
 */
const hasNotificationBeenSent = (activityId, notificationType) => {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT COUNT(*) as count 
      FROM notification 
      WHERE Activity_ID = ? 
      AND Notification_Type = ?
      AND Notification_IsSent = TRUE
      LIMIT 1
    `;
    
    db.query(sql, [activityId, notificationType], (err, results) => {
      if (err) return reject(err);
      resolve(results[0].count > 0);
    });
  });
};

/**
 * Format datetime เป็นภาษาไทย
 */
const formatDateTimeThai = (date) => {
  return date.toLocaleDateString('th-TH', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

// ===================== NOTIFICATION FUNCTIONS =====================

/**
 * 1. แจ้งเตือนเมื่อสร้างกิจกรรมใหม่
 */
const sendActivityCreatedNotification = async (activityId) => {
  try {
    const activitySql = `
      SELECT a.*, at.ActivityType_Name 
      FROM activity a 
      LEFT JOIN activitytype at ON a.ActivityType_ID = at.ActivityType_ID 
      WHERE a.Activity_ID = ?
    `;
    
    const activity = await new Promise((resolve, reject) => {
      db.query(activitySql, [activityId], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    if (!activity) return;

    const eligibleUsers = await getEligibleUsersForActivity(activityId);
    
    if (eligibleUsers.length === 0) {
      console.log(`No eligible users for activity ${activityId}`);
      return;
    }

    const title = `กิจกรรมใหม่: ${activity.Activity_Title}`;
    const body = `มีกิจกรรมใหม่เปิดให้ลงทะเบียน - ${activity.Activity_Title}`;
    const formattedDate = formatDateTimeThai(new Date(activity.Activity_StartTime));
    
    const data = {
      type: 'activity_created',
      activity_id: activityId.toString(),
      notification_type: 'created'
    };

    const result = await sendNotificationToMultipleUsers(eligibleUsers, title, body, data);
    
    const detail = `กิจกรรมใหม่: ${activity.Activity_Title} (${formattedDate})`;
    await saveNotificationForUsers(eligibleUsers, title, detail, activityId, 'created');
    
    console.log(`✅ Sent 'created' notification for activity ${activityId}:`, result);
  } catch (error) {
    console.error(`Error sending created notification for activity ${activityId}:`, error);
  }
};

/**
 * 2. แจ้งเตือนเมื่ออัปเดตกิจกรรม
 */
const sendActivityUpdatedNotification = async (activityId, updateType = 'general') => {
  try {
    const activitySql = `
      SELECT a.*, at.ActivityType_Name 
      FROM activity a 
      LEFT JOIN activitytype at ON a.ActivityType_ID = at.ActivityType_ID 
      WHERE a.Activity_ID = ?
    `;
    
    const activity = await new Promise((resolve, reject) => {
      db.query(activitySql, [activityId], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    if (!activity) return;

    const registeredUsers = await getRegisteredUsersForActivity(activityId);
    const eligibleUsers = await getEligibleUsersForActivity(activityId);
    const allUsers = [...new Set([...registeredUsers, ...eligibleUsers])];
    
    if (allUsers.length === 0) return;

    const title = `อัปเดตกิจกรรม: ${activity.Activity_Title}`;
    const body = `มีการเปลี่ยนแปลงรายละเอียดกิจกรรม - ${activity.Activity_Title}`;
    const formattedDate = formatDateTimeThai(new Date(activity.Activity_StartTime));
    
    const data = {
      type: 'activity_updated',
      activity_id: activityId.toString(),
      notification_type: 'updated',
      update_type: updateType
    };

    const result = await sendNotificationToMultipleUsers(allUsers, title, body, data);
    
    const detail = `กิจกรรม ${activity.Activity_Title} มีการอัปเดตข้อมูล (${formattedDate})`;
    await saveNotificationForUsers(allUsers, title, detail, activityId, 'updated');
    
    console.log(`✅ Sent 'updated' notification for activity ${activityId}:`, result);
  } catch (error) {
    console.error(`Error sending updated notification for activity ${activityId}:`, error);
  }
};

/**
 * 3. แจ้งเตือนเมื่อถึงเวลาเริ่มกิจกรรม (ใหม่: เพิ่ม cron job)
 */
const sendActivityStartingNotification = async (activityId) => {
  try {
    const activitySql = `
      SELECT a.*, at.ActivityType_Name 
      FROM activity a 
      LEFT JOIN activitytype at ON a.ActivityType_ID = at.ActivityType_ID 
      WHERE a.Activity_ID = ? 
      AND a.ActivityStatus_ID IN (
        SELECT ActivityStatus_ID FROM activitystatus 
        WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
      )
    `;
    
    const activity = await new Promise((resolve, reject) => {
      db.query(activitySql, [activityId], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    if (!activity) return;

    const registeredUsers = await getRegisteredUsersForActivity(activityId);
    
    if (registeredUsers.length === 0) return;

    const title = `กิจกรรมกำลังจะเริ่ม: ${activity.Activity_Title}`;
    const body = `กิจกรรม ${activity.Activity_Title} กำลังจะเริ่มแล้ว เตรียมตัวเข้าร่วมกิจกรรม`;
    
    const data = {
      type: 'activity_starting',
      activity_id: activityId.toString(),
      notification_type: 'starting'
    };

    const result = await sendNotificationToMultipleUsers(registeredUsers, title, body, data);
    
    const detail = `กิจกรรม ${activity.Activity_Title} กำลังจะเริ่มแล้ว`;
    await saveNotificationForUsers(registeredUsers, title, detail, activityId, 'starting');
    
    console.log(`✅ Sent 'starting' notification for activity ${activityId}:`, result);
  } catch (error) {
    console.error(`Error sending starting notification for activity ${activityId}:`, error);
  }
};

/**
 * ✨ ใหม่: ตรวจสอบและส่งแจ้งเตือนเมื่อใกล้เวลาเริ่มกิจกรรม
 */
const checkAndSendStartingNotifications = async () => {
  try {
    const now = new Date();
    const in30Minutes = new Date(now.getTime() + 30 * 60 * 1000);

    const sql = `
      SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
      FROM activity a 
      WHERE a.Activity_StartTime BETWEEN ? AND ?
      AND a.ActivityStatus_ID IN (
        SELECT ActivityStatus_ID FROM activitystatus 
        WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
      )
    `;

    db.query(sql, [now, in30Minutes], async (err, activities) => {
      if (err) {
        console.error('Error fetching starting activities:', err);
        return;
      }

      for (const activity of activities) {
        try {
          const alreadySent = await hasNotificationBeenSent(activity.Activity_ID, 'starting');
          if (alreadySent) continue;

          await sendActivityStartingNotification(activity.Activity_ID);
        } catch (error) {
          console.error(`Error processing starting activity ${activity.Activity_ID}:`, error);
        }
      }
    });
  } catch (error) {
    console.error('Error in checkAndSendStartingNotifications:', error);
  }
};

/**
 * 4. แจ้งเตือนเมื่อกิจกรรมสิ้นสุด
 */
const sendActivityEndedNotification = async (activityId) => {
  try {
    const activitySql = `
      SELECT a.*, at.ActivityType_Name 
      FROM activity a 
      LEFT JOIN activitytype at ON a.ActivityType_ID = at.ActivityType_ID 
      WHERE a.Activity_ID = ?
    `;
    
    const activity = await new Promise((resolve, reject) => {
      db.query(activitySql, [activityId], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    if (!activity) return;

    const registeredUsers = await getRegisteredUsersForActivity(activityId);
    
    if (registeredUsers.length === 0) return;

    const title = `กิจกรรมสิ้นสุด: ${activity.Activity_Title}`;
    const body = `กิจกรรม ${activity.Activity_Title} สิ้นสุดแล้ว ขอบคุณที่เข้าร่วมกิจกรรม`;
    
    const data = {
      type: 'activity_ended',
      activity_id: activityId.toString(),
      notification_type: 'ended'
    };

    const result = await sendNotificationToMultipleUsers(registeredUsers, title, body, data);
    
    const detail = `กิจกรรม ${activity.Activity_Title} สิ้นสุดแล้ว อย่าลืมอัปโหลดรูปภาพกิจกรรม`;
    await saveNotificationForUsers(registeredUsers, title, detail, activityId, 'ended');
    
    console.log(`✅ Sent 'ended' notification for activity ${activityId}:`, result);
  } catch (error) {
    console.error(`Error sending ended notification for activity ${activityId}:`, error);
  }
};

/**
 * ✨ ใหม่: ตรวจสอบและส่งแจ้งเตือนเมื่อกิจกรรมสิ้นสุด
 */
const checkAndSendEndedNotifications = async () => {
  try {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const sql = `
      SELECT a.Activity_ID, a.Activity_Title, a.Activity_EndTime 
      FROM activity a 
      WHERE a.Activity_EndTime BETWEEN ? AND ?
      AND a.ActivityStatus_ID IN (
        SELECT ActivityStatus_ID FROM activitystatus 
        WHERE ActivityStatus_Name = 'เสร็จสิ้น'
      )
    `;

    db.query(sql, [oneHourAgo, now], async (err, activities) => {
      if (err) {
        console.error('Error fetching ended activities:', err);
        return;
      }

      for (const activity of activities) {
        try {
          const alreadySent = await hasNotificationBeenSent(activity.Activity_ID, 'ended');
          if (alreadySent) continue;

          await sendActivityEndedNotification(activity.Activity_ID);
        } catch (error) {
          console.error(`Error processing ended activity ${activity.Activity_ID}:`, error);
        }
      }
    });
  } catch (error) {
    console.error('Error in checkAndSendEndedNotifications:', error);
  }
};

/**
 * 5-8. แจ้งเตือนก่อนกิจกรรม (7 วัน, 3 วัน, 1 วัน, วันเดียวกัน)
 */
const checkAndSendReminderNotifications = async () => {
  try {
    const now = new Date();
    const in7Days = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const in3Days = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);
    const in1Day = new Date(now.getTime() + 1 * 24 * 60 * 60 * 1000);

    const notificationQueries = [
      {
        type: '7days',
        sql: `
          SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
          FROM activity a 
          WHERE DATE(a.Activity_StartTime) = DATE(?) 
          AND a.ActivityStatus_ID IN (
            SELECT ActivityStatus_ID FROM activitystatus 
            WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
          )
        `,
        date: in7Days,
        message: 'อีก 7 วันจะถึงกิจกรรม'
      },
      {
        type: '3days',
        sql: `
          SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
          FROM activity a 
          WHERE DATE(a.Activity_StartTime) = DATE(?) 
          AND a.ActivityStatus_ID IN (
            SELECT ActivityStatus_ID FROM activitystatus 
            WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
          )
        `,
        date: in3Days,
        message: 'อีก 3 วันจะถึงกิจกรรม'
      },
      {
        type: '1day',
        sql: `
          SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
          FROM activity a 
          WHERE DATE(a.Activity_StartTime) = DATE(?) 
          AND a.ActivityStatus_ID IN (
            SELECT ActivityStatus_ID FROM activitystatus 
            WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
          )
        `,
        date: in1Day,
        message: 'พรุ่งนี้จะมีกิจกรรม'
      },
      {
        type: 'today',
        sql: `
          SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
          FROM activity a 
          WHERE DATE(a.Activity_StartTime) = CURDATE() 
          AND a.ActivityStatus_ID IN (
            SELECT ActivityStatus_ID FROM activitystatus 
            WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
          )
        `,
        date: now,
        message: 'วันนี้มีกิจกรรม'
      }
    ];

    for (const query of notificationQueries) {
      db.query(query.sql, [query.date], async (err, activities) => {
        if (err) {
          console.error(`Error fetching activities for ${query.type}:`, err);
          return;
        }

        for (const activity of activities) {
          try {
            const alreadySent = await hasNotificationBeenSent(activity.Activity_ID, query.type);
            if (alreadySent) {
              console.log(`Notification ${query.type} already sent for activity ${activity.Activity_ID}`);
              continue;
            }

            const eligibleUsers = await getEligibleUsersForActivity(activity.Activity_ID);
            
            if (eligibleUsers.length === 0) {
              console.log(`No eligible users for activity ${activity.Activity_ID}`);
              continue;
            }

            const title = `แจ้งเตือนกิจกรรม: ${activity.Activity_Title}`;
            const body = `${query.message} - ${activity.Activity_Title}`;
            const formattedDate = formatDateTimeThai(new Date(activity.Activity_StartTime));

            const data = {
              type: 'activity_reminder',
              activity_id: activity.Activity_ID.toString(),
              notification_type: query.type,
              start_time: activity.Activity_StartTime.toISOString()
            };

            const result = await sendNotificationToMultipleUsers(eligibleUsers, title, body, data);

            console.log(`[${new Date().toISOString()}] Sent ${query.type} notification for activity ${activity.Activity_ID}:`, result);

            const notificationDetail = `${query.message} - ${activity.Activity_Title} (${formattedDate})`;
            await saveNotificationForUsers(eligibleUsers, title, notificationDetail, activity.Activity_ID, query.type);
          } catch (error) {
            console.error(`Error processing activity ${activity.Activity_ID}:`, error);
          }
        }
      });
    }
  } catch (error) {
    console.error('Error in checkAndSendReminderNotifications:', error);
  }
};

/**
 * แจ้งเตือนเวลา 6 โมงเช้าของวันกิจกรรม
 */
const send6AMActivityReminder = async () => {
  try {
    const sql = `
      SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime 
      FROM activity a 
      WHERE DATE(a.Activity_StartTime) = CURDATE() 
      AND a.ActivityStatus_ID IN (
        SELECT ActivityStatus_ID FROM activitystatus 
        WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
      )
    `;

    db.query(sql, [], async (err, activities) => {
      if (err) {
        console.error('Error fetching activities for 6AM reminder:', err);
        return;
      }

      for (const activity of activities) {
        try {
          const alreadySent = await hasNotificationBeenSent(activity.Activity_ID, '6am');
          if (alreadySent) continue;

          const registeredUsers = await getRegisteredUsersForActivity(activity.Activity_ID);
          
          if (registeredUsers.length === 0) continue;

          const title = `เตือนความจำ: กิจกรรมวันนี้`;
          const body = `อย่าลืม! วันนี้มีกิจกรรม ${activity.Activity_Title}`;
          const formattedDate = formatDateTimeThai(new Date(activity.Activity_StartTime));

          const data = {
            type: 'activity_reminder',
            activity_id: activity.Activity_ID.toString(),
            notification_type: '6am'
          };

          const result = await sendNotificationToMultipleUsers(registeredUsers, title, body, data);

          const detail = `เตือนความจำ: วันนี้มีกิจกรรม ${activity.Activity_Title} (${formattedDate})`;
          await saveNotificationForUsers(registeredUsers, title, detail, activity.Activity_ID, '6am');

          console.log(`✅ Sent 6AM reminder for activity ${activity.Activity_ID}:`, result);
        } catch (error) {
          console.error(`Error sending 6AM reminder for activity ${activity.Activity_ID}:`, error);
        }
      }
    });
  } catch (error) {
    console.error('Error in send6AMActivityReminder:', error);
  }
};

// ===================== CRON JOBS =====================

const initActivityNotificationCron = () => {
  console.log('[Activity Notification Scheduler] Initializing...');

  // ตรวจสอบทุกชั่วโมง (7 วัน, 3 วัน, 1 วัน, วันเดียวกัน)
  cron.schedule('0 * * * *', () => {
    console.log(`[${new Date().toISOString()}] Running hourly reminder check...`);
    checkAndSendReminderNotifications();
  });

  // แจ้งเตือนเวลา 6 โมงเช้า
  cron.schedule('0 6 * * *', () => {
    console.log(`[${new Date().toISOString()}] Running 6AM reminder...`);
    send6AMActivityReminder();
  });

  // แจ้งเตือนเวลา 9 โมงเช้า
  cron.schedule('0 9 * * *', () => {
    console.log(`[${new Date().toISOString()}] Running 9AM reminder...`);
    checkAndSendReminderNotifications();
  });

  // ✨ ใหม่: ตรวจสอบกิจกรรมที่กำลังจะเริ่ม (ทุก 10 นาที)
  cron.schedule('*/10 * * * *', () => {
    console.log(`[${new Date().toISOString()}] Checking for starting activities...`);
    checkAndSendStartingNotifications();
  });

  // ✨ ใหม่: ตรวจสอบกิจกรรมที่เพิ่งจบ (ทุก 30 นาที)
  cron.schedule('*/30 * * * *', () => {
    console.log(`[${new Date().toISOString()}] Checking for ended activities...`);
    checkAndSendEndedNotifications();
  });

  console.log('✓ Activity notification cron jobs initialized');
  console.log('  - Hourly reminder check: 0 * * * *');
  console.log('  - Daily 6AM reminder: 0 6 * * *');
  console.log('  - Daily 9AM reminder: 0 9 * * *');
  console.log('  - Starting activities check (every 10 min): */10 * * * *');
  console.log('  - Ended activities check (every 30 min): */30 * * * *');
};

// ===================== EXPORTS =====================

module.exports = {
  initActivityNotificationCron,
  checkAndSendReminderNotifications,
  sendActivityCreatedNotification,
  sendActivityUpdatedNotification,
  sendActivityStartingNotification,
  sendActivityEndedNotification,
  send6AMActivityReminder,
  checkAndSendStartingNotifications,
  checkAndSendEndedNotifications,
  getEligibleUsersForActivity,
  getRegisteredUsersForActivity
};