const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');

const initializeFirebase = () => {
  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
      });
      console.log('✓ Firebase Admin initialized successfully');
    }
  } catch (error) {
    console.error('Error initializing Firebase Admin:', error);
  }
};

module.exports = {
  admin,
  initializeFirebase
};