const cron = require('node-cron');
const db = require('../Server_Services/databaseClient');
const { sendNotificationToMultipleUsers, saveNotificationForUsers } = require('../FCM_Services/notificationService');

const checkAndSendActivityNotifications = async () => {
  try {
    const now = new Date();
    
    const in7Days = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const in3Days = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);
    const in1Day = new Date(now.getTime() + 1 * 24 * 60 * 60 * 1000);

    const notificationQueries = [
      {
        type: '7days',
        sql: `SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime, a.Activity_Description 
              FROM activity a 
              WHERE DATE(a.Activity_StartTime) = DATE(?) 
              AND a.ActivityStatus_ID = (SELECT ActivityStatus_ID FROM activitystatus WHERE ActivityStatus_Name = 'เปิดรับสมัคร')
              AND NOT EXISTS (
                SELECT 1 FROM notification n 
                WHERE n.Activity_ID = a.Activity_ID 
                AND n.Notification_Type = '7days'
                AND DATE(n.Notification_RegisTime) = CURDATE()
              )`,
        date: in7Days,
        message: 'อีก 7 วันจะถึงกิจกรรม'
      },
      {
        type: '3days',
        sql: `SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime, a.Activity_Description 
              FROM activity a 
              WHERE DATE(a.Activity_StartTime) = DATE(?) 
              AND a.ActivityStatus_ID IN (
                SELECT ActivityStatus_ID FROM activitystatus 
                WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
              )
              AND NOT EXISTS (
                SELECT 1 FROM notification n 
                WHERE n.Activity_ID = a.Activity_ID 
                AND n.Notification_Type = '3days'
                AND DATE(n.Notification_RegisTime) = CURDATE()
              )`,
        date: in3Days,
        message: 'อีก 3 วันจะถึงกิจกรรม'
      },
      {
        type: '1day',
        sql: `SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime, a.Activity_Description 
              FROM activity a 
              WHERE DATE(a.Activity_StartTime) = DATE(?) 
              AND a.ActivityStatus_ID IN (
                SELECT ActivityStatus_ID FROM activitystatus 
                WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
              )
              AND NOT EXISTS (
                SELECT 1 FROM notification n 
                WHERE n.Activity_ID = a.Activity_ID 
                AND n.Notification_Type = '1day'
                AND DATE(n.Notification_RegisTime) = CURDATE()
              )`,
        date: in1Day,
        message: 'พรุ่งนี้จะมีกิจกรรม'
      },
      {
        type: 'today',
        sql: `SELECT a.Activity_ID, a.Activity_Title, a.Activity_StartTime, a.Activity_Description 
              FROM activity a 
              WHERE DATE(a.Activity_StartTime) = CURDATE()
              AND a.ActivityStatus_ID IN (
                SELECT ActivityStatus_ID FROM activitystatus 
                WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ')
              )
              AND NOT EXISTS (
                SELECT 1 FROM notification n 
                WHERE n.Activity_ID = a.Activity_ID 
                AND n.Notification_Type = 'today'
                AND DATE(n.Notification_RegisTime) = CURDATE()
              )`,
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
            const usersSql = `SELECT DISTINCT r.Users_ID 
                             FROM registration r 
                             WHERE r.Activity_ID = ?`;
            
            db.query(usersSql, [activity.Activity_ID], async (err, users) => {
              if (err) {
                console.error('Error fetching users:', err);
                return;
              }

              if (users.length === 0) {
                console.log(`No registered users for activity ${activity.Activity_ID}`);
                return;
              }

              const userIds = users.map(u => u.Users_ID);
              const title = `แจ้งเตือนกิจกรรม: ${activity.Activity_Title}`;
              const body = `${query.message} - ${activity.Activity_Title}`;
              
              const startDate = new Date(activity.Activity_StartTime);
              const formattedDate = startDate.toLocaleDateString('th-TH', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
              });

              const data = {
                type: 'activity_reminder',
                activity_id: activity.Activity_ID.toString(),
                notification_type: query.type,
                start_time: activity.Activity_StartTime.toISOString()
              };

              const result = await sendNotificationToMultipleUsers(userIds, title, body, data);
              
              console.log(`[${new Date().toISOString()}] Sent ${query.type} notification for activity ${activity.Activity_ID}:`, result);

              const notificationDetail = `${query.message} - ${activity.Activity_Title} (${formattedDate})`;
              await saveNotificationForUsers(userIds, title, notificationDetail, activity.Activity_ID, query.type);
            });
          } catch (error) {
            console.error(`Error processing activity ${activity.Activity_ID}:`, error);
          }
        }
      });
    }
  } catch (error) {
    console.error('Error in checkAndSendActivityNotifications:', error);
  }
};

const initActivityNotificationCron = () => {
  console.log('[Activity Notification Scheduler] Initializing...');

  cron.schedule('0 * * * *', () => {
    console.log(`[${new Date().toISOString()}] Running hourly activity notification check...`);
    checkAndSendActivityNotifications();
  });

  cron.schedule('0 6 * * *', () => {
    console.log(`[${new Date().toISOString()}] Running 6AM activity notification...`);
    checkAndSendActivityNotifications();
  });

  cron.schedule('0 9 * * *', () => {
    console.log(`[${new Date().toISOString()}] Running 9AM activity notification check...`);
    checkAndSendActivityNotifications();
  });

  console.log('✓ Activity notification cron jobs initialized');
  console.log('  - Hourly check: 0 * * * *');
  console.log('  - Daily 6AM: 0 6 * * *');
  console.log('  - Daily 9AM: 0 9 * * *');
};

module.exports = {
  initActivityNotificationCron,
  checkAndSendActivityNotifications
};