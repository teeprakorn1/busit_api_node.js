const cron = require('node-cron');
const db = require('../Server_Services/databaseClient');

const updateActivityStatus = async () => {
  try {
    const now = new Date();

    const updateToOngoingSql = `UPDATE activity SET ActivityStatus_ID = ( 
      SELECT ActivityStatus_ID FROM activitystatus WHERE ActivityStatus_Name = 'กำลังดำเนินการ')
      WHERE Activity_StartTime <= ? AND Activity_EndTime > ? AND ActivityStatus_ID = ( SELECT ActivityStatus_ID 
      FROM activitystatus WHERE ActivityStatus_Name = 'เปิดรับสมัคร')`;

    const updateToCompletedSql = `UPDATE activity SET ActivityStatus_ID = ( 
      SELECT ActivityStatus_ID FROM activitystatus WHERE ActivityStatus_Name = 'เสร็จสิ้น') 
      WHERE Activity_EndTime <= ? AND ActivityStatus_ID IN ( SELECT ActivityStatus_ID FROM activitystatus 
      WHERE ActivityStatus_Name IN ('เปิดรับสมัคร', 'กำลังดำเนินการ'))`;

    db.query(updateToOngoingSql, [now, now], (err, result) => {
      if (err) {
        console.error('[Activity Status Updater] Error updating to ongoing:', err);
      } else if (result && result.affectedRows > 0) {
        console.log(`[${new Date().toISOString()}] ✓ Updated ${result.affectedRows} activity(ies) to "กำลังดำเนินการ"`);
      }
    });

    db.query(updateToCompletedSql, [now], (err, result) => {
      if (err) {
        console.error('[Activity Status Updater] Error updating to completed:', err);
      } else if (result && result.affectedRows > 0) {
        console.log(`[${new Date().toISOString()}] ✓ Updated ${result.affectedRows} activity(ies) to "เสร็จสิ้น"`);
      }
    });

  } catch (error) {
    console.error('[Activity Status Updater] Unexpected error:', error);
  }
};

const initActivityStatusCron = () => {
  console.log('[Activity Status Updater] Running initial status update...');
  updateActivityStatus();

  cron.schedule('*/1 * * * *', () => {
    console.log(`[${new Date().toISOString()}] Running scheduled activity status update (every 1 minutes)...`);
    updateActivityStatus();
  });

  cron.schedule('0 0 * * *', () => {
    console.log(`[${new Date().toISOString()}] Running daily activity status update (midnight)...`);
    updateActivityStatus();
  });

  console.log('✓ Activity status cron jobs initialized successfully');
  console.log('  - Every 1 minutes: */1 * * * *');
  console.log('  - Daily at midnight: 0 0 * * *');
};

module.exports = {
  initActivityStatusCron,
  updateActivityStatus
};