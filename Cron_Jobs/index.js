const { initActivityStatusCron, updateActivityStatus } = require('./activityStatusUpdater');
const { initActivityNotificationCron, checkAndSendActivityNotifications } = require('./activityNotificationScheduler');

const initAllCronJobs = () => {
  console.log('\n========================================');
  console.log('Initializing Cron Jobs...');
  console.log('========================================');
  
  try {
    initActivityStatusCron();
    initActivityNotificationCron();
    
    console.log('========================================');
    console.log('All Cron Jobs initialized successfully');
    console.log('========================================\n');
  } catch (error) {
    console.error('Error initializing cron jobs:', error);
  }
};

module.exports = {
  initAllCronJobs,
  updateActivityStatus,
  checkAndSendActivityNotifications
};