const { admin } = require('./firebaseConfig');
const db = require('../Server_Services/databaseClient');

/**
 * ส่ง FCM notification ไปยังผู้ใช้หลายคน
 */
const sendNotificationToMultipleUsers = async (userIds, title, body, data = {}) => {
  try {
    if (!userIds || userIds.length === 0) {
      console.log('⚠️ No users to send notification');
      return { success: 0, failure: 0, total: 0 };
    }

    console.log(`📤 Sending notification to ${userIds.length} users...`);

    // ดึง FCM tokens
    const tokens = await getFCMTokensByUserIds(userIds);
    
    if (tokens.length === 0) {
      console.log('⚠️ No active FCM tokens found');
      return { success: 0, failure: 0, total: 0 };
    }

    // สร้าง message payload
    const message = {
      notification: {
        title: title,
        body: body,
      },
      data: {
        ...data,
        click_action: 'FLUTTER_NOTIFICATION_CLICK',
        title: title,
        body: body,
      },
      android: {
        priority: 'high',
        notification: {
          channelId: 'activity_channel',
          priority: 'high',
          defaultSound: true,
          defaultVibrateTimings: true,
          defaultLightSettings: true,
          color: '#001B3F',
          icon: 'ic_launcher',
          sound: 'default',
          clickAction: 'FLUTTER_NOTIFICATION_CLICK',
        },
      },
      apns: {
        payload: {
          aps: {
            alert: {
              title: title,
              body: body,
            },
            sound: 'default',
            badge: 1,
            'content-available': 1,
          },
        },
        headers: {
          'apns-priority': '10',
          'apns-push-type': 'alert',
        },
      },
    };

    // ส่ง notification
    const results = await sendMulticastNotification(tokens, message);
    
    console.log(`✅ Notification sent: ${results.successCount} success, ${results.failureCount} failed`);
    
    // ลบ tokens ที่ invalid
    if (results.invalidTokens.length > 0) {
      await removeInvalidTokens(results.invalidTokens);
    }

    return {
      success: results.successCount,
      failure: results.failureCount,
      total: tokens.length
    };

  } catch (error) {
    console.error('❌ Error sending notification:', error);
    return { success: 0, failure: userIds.length, total: userIds.length };
  }
};

/**
 * ส่ง notification แบบ multicast (batch)
 */
const sendMulticastNotification = async (tokens, message) => {
  const batchSize = 500; // FCM limit
  let successCount = 0;
  let failureCount = 0;
  const invalidTokens = [];

  for (let i = 0; i < tokens.length; i += batchSize) {
    const batch = tokens.slice(i, i + batchSize);
    
    try {
      const response = await admin.messaging().sendEachForMulticast({
        tokens: batch,
        ...message
      });

      successCount += response.successCount;
      failureCount += response.failureCount;

      // เก็บ tokens ที่ invalid
      response.responses.forEach((resp, idx) => {
        if (!resp.success) {
          const error = resp.error?.code;
          if (error === 'messaging/invalid-registration-token' || 
              error === 'messaging/registration-token-not-registered') {
            invalidTokens.push(batch[idx]);
          }
          if (error) {
            console.warn(`  Failed: ${error}`);
          }
        }
      });

    } catch (error) {
      console.error('  Error sending batch:', error.message);
      failureCount += batch.length;
    }
  }

  return { successCount, failureCount, invalidTokens };
};

/**
 * ดึง FCM tokens ของผู้ใช้
 */
const getFCMTokensByUserIds = (userIds) => {
  return new Promise((resolve, reject) => {
    if (!userIds || userIds.length === 0) {
      return resolve([]);
    }

    const placeholders = userIds.map(() => '?').join(',');
    const sql = `
      SELECT DISTINCT FCM_Token 
      FROM FCMTokens 
      WHERE Users_ID IN (${placeholders})
      AND FCMToken_IsActive = TRUE
      AND FCM_Token IS NOT NULL
      AND FCM_Token != ''
    `;

    db.query(sql, userIds, (err, results) => {
      if (err) {
        console.error('Error fetching FCM tokens:', err);
        return reject(err);
      }
      
      const tokens = results.map(r => r.FCM_Token).filter(Boolean);
      console.log(`📱 Found ${tokens.length} active FCM tokens`);
      resolve(tokens);
    });
  });
};

/**
 * ลบ FCM tokens ที่ invalid
 */
const removeInvalidTokens = async (tokens) => {
  if (!tokens || tokens.length === 0) return;

  return new Promise((resolve, reject) => {
    const placeholders = tokens.map(() => '?').join(',');
    const sql = `
      UPDATE FCMTokens 
      SET FCMToken_IsActive = FALSE 
      WHERE FCM_Token IN (${placeholders})
    `;

    db.query(sql, tokens, (err, result) => {
      if (err) {
        console.error('Error removing invalid tokens:', err);
        return reject(err);
      }
      console.log(`🗑️ Removed ${result.affectedRows} invalid tokens`);
      resolve(result);
    });
  });
};

/**
 * บันทึก notification ลง database
 */
const saveNotificationForUsers = async (userIds, title, detail, activityId, type) => {
  if (!userIds || userIds.length === 0) return;

  return new Promise((resolve, reject) => {
    const values = userIds.map(userId => [
      userId,
      title,
      detail,
      activityId,
      type,
      true // Notification_IsSent
    ]);

    const sql = `
      INSERT INTO notification 
      (Users_ID, Notification_Title, Notification_Detail, Activity_ID, Notification_Type, Notification_IsSent)
      VALUES ?
    `;

    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error('Error saving notifications:', err);
        return reject(err);
      }
      console.log(`💾 Saved ${result.affectedRows} notifications to database`);
      resolve(result);
    });
  });
};

/**
 * ส่ง notification ไปยังผู้ใช้คนเดียว
 */
const sendNotificationToUser = async (userId, title, body, data = {}) => {
  return sendNotificationToMultipleUsers([userId], title, body, data);
};

module.exports = {
  sendNotificationToMultipleUsers,
  sendNotificationToUser,
  saveNotificationForUsers,
  getFCMTokensByUserIds
};