const { admin } = require('./firebaseConfig');
const db = require('../Server_Services/databaseClient');

const sendNotificationToUser = async (userId, title, body, data = {}) => {
  try {
    const sql = `SELECT FCM_Token FROM fcmtokens WHERE Users_ID = ? AND FCMToken_IsActive = TRUE`;

    return new Promise((resolve, reject) => {
      db.query(sql, [userId], async (err, results) => {
        if (err) {
          console.error('Error fetching FCM tokens:', err);
          return reject(err);
        }

        if (results.length === 0) {
          return resolve({ success: false, message: 'No tokens found' });
        }

        const tokens = results.map(row => row.FCM_Token);

        const message = {
          notification: {
            title,
            body,
          },
          data: {
            ...data,
            click_action: 'FLUTTER_NOTIFICATION_CLICK',
            timestamp: new Date().toISOString()
          },
          android: {
            priority: 'high',
            notification: {
              channelId: 'activity_channel',
              priority: 'high',
              defaultSound: true,
              defaultVibrateTimings: true,
              defaultLightSettings: true,
              sound: 'notification_sound',
              color: '#001B3F',
              visibility: 'public',
            }
          },
          apns: {
            payload: {
              aps: {
                sound: 'notification_sound.caf',
                badge: 1,
                alert: {
                  title,
                  body
                },
                'interruption-level': 'time-sensitive'
              }
            }
          },
          tokens: tokens
        };

        try {
          const response = await admin.messaging().sendEachForMulticast(message);

          console.log(`✅ Sent notification to user ${userId}:`, {
            successCount: response.successCount,
            failureCount: response.failureCount
          });
          if (response.failureCount > 0) {
            const failedTokens = [];
            response.responses.forEach((resp, idx) => {
              if (!resp.success) {
                failedTokens.push(tokens[idx]);
                console.error(`Token failed: ${tokens[idx]}, Error:`, resp.error);
              }
            });
            if (failedTokens.length > 0) {
              const deactivateSql = `UPDATE fcmtokens SET FCMToken_IsActive = FALSE WHERE FCM_Token IN (?)`;
              db.query(deactivateSql, [failedTokens], (err) => {
                if (err) console.error('Error deactivating tokens:', err);
                else console.log(`Deactivated ${failedTokens.length} failed tokens`);
              });
            }
          }

          resolve({
            success: true,
            successCount: response.successCount,
            failureCount: response.failureCount
          });
        } catch (error) {
          console.error('Error sending FCM notification:', error);
          reject(error);
        }
      });
    });
  } catch (error) {
    console.error('Error in sendNotificationToUser:', error);
    throw error;
  }
};

const sendNotificationToMultipleUsers = async (userIds, title, body, data = {}) => {
  const results = {
    total: userIds.length,
    success: 0,
    failed: 0
  };

  for (const userId of userIds) {
    try {
      const result = await sendNotificationToUser(userId, title, body, data);
      if (result.success) {
        results.success++;
      } else {
        results.failed++;
      }
    } catch (error) {
      results.failed++;
      console.error(`Failed to send notification to user ${userId}:`, error);
    }
  }

  return results;
};

const saveNotificationForUsers = async (userIds, title, detail, activityId, notificationType) => {
  return new Promise((resolve, reject) => {
    const values = userIds.map(userId => [
      title,
      detail,
      notificationType,
      true,
      userId,
      activityId
    ]);

    const sql = `INSERT INTO notification 
      (Notification_Title, Notification_Detail, Notification_Type, Notification_IsSent, Users_ID, Activity_ID) 
      VALUES ?`;

    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error('Error saving notifications to database:', err);
        return reject(err);
      }
      console.log(`Saved ${result.affectedRows} notifications to database`);
      resolve(result);
    });
  });
};

module.exports = {
  sendNotificationToUser,
  sendNotificationToMultipleUsers,
  saveNotificationForUsers
};