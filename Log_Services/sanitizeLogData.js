function sanitizeLogData(data) {
  const sanitized = { ...data };

  const sensitiveFields = ['password', 'otp', 'token', 'Users_Password'];
  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[MASKED]';
    }
  }

  return sanitized;
}

module.exports = sanitizeLogData;
