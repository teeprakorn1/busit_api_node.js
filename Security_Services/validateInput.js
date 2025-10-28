const validator = require('validator');

function toBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }
  if (value === 1 || value === '1') return true;
  if (value === 0 || value === '0') return false;
  return null;
}

function validatePasswordComplexity(pw) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,127}$/.test(pw);
}

function validateInput(req, res, next) {
  const errors = [];
  const body = req.body;

  if ('Users_Email' in body) {
    if (!validator.isEmail(body.Users_Email)) {
      errors.push('Users_Email must be a valid email address');
    }
  }

  if ('Users_Username' in body) {
    if (validator.isEmpty(body.Users_Username)) {
      errors.push('Users_Username cannot be empty');
    } else if (!validator.isLength(body.Users_Username, { min: 3, max: 63 })) {
      errors.push('Users_Username must be between 3 and 63 characters');
    } else if (/\s/.test(body.Users_Username)) {
      errors.push('Users_Username cannot contain spaces');
    }
  }

  if ('Users_Password' in body) {
    if (!validatePasswordComplexity(body.Users_Password)) {
      errors.push('Users_Password must be at least 8 characters with uppercase, lowercase letters and numbers');
    }
  }

  const allowedUserTypes = ['teacher', 'student', 'staff', 'admin'];

  if ('Users_Type' in body && body.Users_Type !== '') {
    if (!allowedUserTypes.includes(body.Users_Type)) {
      errors.push(`Users_Type must be one of: ${allowedUserTypes.join(', ')}`);
    }
  }

  if ('Users_IsActive' in body) {
    const boolVal = toBoolean(body.Users_IsActive);
    if (boolVal === null) {
      errors.push('Users_IsActive must be a boolean');
    } else {
      body.Users_IsActive = boolVal;
    }
  }

  if ('Users_ImageFile' in body && body.Users_ImageFile) {
    if (!validator.isLength(body.Users_ImageFile, { max: 255 })) {
      errors.push('Users_ImageFile must be no more than 255 characters');
    }
  }

  const foreignKeyFields = [
    'Users_ID', 'Department_ID', 'Teacher_ID', 'Staff_ID',
    'Faculty_ID', 'DataEditType_ID', 'TimestampType_ID',
    'ActivityStatus_ID', 'RegistrationStatus_ID', 'RegistrationPictureStatus_ID',
    'Activity_ID',
  ];
  foreignKeyFields.forEach(field => {
    if (field in body) {
      if (!validator.isInt(body[field] + '', { min: 1 })) {
        errors.push(`${field} must be a positive integer`);
      }
    }
  });

  if ('Teacher_Code' in body && !validator.isLength(body.Teacher_Code || '', { min: 1, max: 15 })) {
    errors.push('Teacher_Code must be no more than 15 characters');
  }
  if ('Teacher_FirstName' in body && validator.isEmpty(body.Teacher_FirstName || '')) {
    errors.push('Teacher_FirstName cannot be empty');
  }
  if ('Teacher_LastName' in body && validator.isEmpty(body.Teacher_LastName || '')) {
    errors.push('Teacher_LastName cannot be empty');
  }
  if ('Teacher_Phone' in body && body.Teacher_Phone) {
    if (!validator.isMobilePhone(body.Teacher_Phone, 'th-TH')) {
      errors.push('Teacher_Phone must be a valid phone number');
    }
  }
  if ('Teacher_Birthdate' in body && body.Teacher_Birthdate) {
    if (!validator.isDate(body.Teacher_Birthdate)) {
      errors.push('Teacher_Birthdate must be a valid date');
    }
  }
  if ('Teacher_Religion' in body && body.Teacher_Religion) {
    if (!validator.isLength(body.Teacher_Religion, { max: 63 })) {
      errors.push('Teacher_Religion must be no more than 63 characters');
    }
  }
  if ('Teacher_MedicalProblem' in body && body.Teacher_MedicalProblem) {
    if (!validator.isLength(body.Teacher_MedicalProblem, { max: 511 })) {
      errors.push('Teacher_MedicalProblem must be no more than 511 characters');
    }
  }
  if ('Teacher_IsResign' in body) {
    const boolVal = toBoolean(body.Teacher_IsResign);
    if (boolVal === null) {
      errors.push('Teacher_IsResign must be a boolean');
    } else {
      body.Teacher_IsResign = boolVal;
    }
  }
  if ('Teacher_IsDean' in body) {
    const boolVal = toBoolean(body.Teacher_IsDean);
    if (boolVal === null) {
      errors.push('Teacher_IsDean must be a boolean');
    } else {
      body.Teacher_IsDean = boolVal;
    }
  }

  if ('Student_Code' in body && !validator.isLength(body.Student_Code || '', { min: 1, max: 15 })) {
    errors.push('Student_Code must be no more than 15 characters');
  }
  if ('Student_FirstName' in body && validator.isEmpty(body.Student_FirstName || '')) {
    errors.push('Student_FirstName cannot be empty');
  }
  if ('Student_LastName' in body && validator.isEmpty(body.Student_LastName || '')) {
    errors.push('Student_LastName cannot be empty');
  }
  if ('Student_Phone' in body && body.Student_Phone) {
    if (!validator.isMobilePhone(body.Student_Phone, 'th-TH')) {
      errors.push('Student_Phone must be a valid phone number');
    }
  }
  if ('Student_AcademicYear' in body) {
    if (!validator.isInt(body.Student_AcademicYear + '', { min: 1900, max: 2100 })) {
      errors.push('Student_AcademicYear must be a valid year');
    }
  }
  if ('Student_Birthdate' in body && body.Student_Birthdate) {
    if (!validator.isDate(body.Student_Birthdate)) {
      errors.push('Student_Birthdate must be a valid date');
    }
  }
  if ('Student_Religion' in body && body.Student_Religion) {
    if (!validator.isLength(body.Student_Religion, { max: 63 })) {
      errors.push('Student_Religion must be no more than 63 characters');
    }
  }
  if ('Student_MedicalProblem' in body && body.Student_MedicalProblem) {
    if (!validator.isLength(body.Student_MedicalProblem, { max: 511 })) {
      errors.push('Student_MedicalProblem must be no more than 511 characters');
    }
  }
  if ('Student_IsGraduated' in body) {
    const boolVal = toBoolean(body.Student_IsGraduated);
    if (boolVal === null) {
      errors.push('Student_IsGraduated must be a boolean');
    } else {
      body.Student_IsGraduated = boolVal;
    }
  }

  if ('Staff_Code' in body && !validator.isLength(body.Staff_Code || '', { min: 1, max: 15 })) {
    errors.push('Staff_Code must be no more than 15 characters');
  }
  if ('Staff_FirstName' in body && validator.isEmpty(body.Staff_FirstName || '')) {
    errors.push('Staff_FirstName cannot be empty');
  }
  if ('Staff_LastName' in body && validator.isEmpty(body.Staff_LastName || '')) {
    errors.push('Staff_LastName cannot be empty');
  }
  if ('Staff_Phone' in body && body.Staff_Phone) {
    if (!validator.isMobilePhone(body.Staff_Phone, 'th-TH')) {
      errors.push('Staff_Phone must be a valid phone number');
    }
  }
  if ('Staff_IsResign' in body) {
    const boolVal = toBoolean(body.Staff_IsResign);
    if (boolVal === null) {
      errors.push('Staff_IsResign must be a boolean');
    } else {
      body.Staff_IsResign = boolVal;
    }
  }

  if ('Users_RegisTime' in body && body.Users_RegisTime) {
    if (!validator.isISO8601(body.Users_RegisTime)) {
      errors.push('Users_RegisTime must be a valid ISO8601 date string');
    }
  }

  ['Users_ImageFile', 'Activity_ImageFile', 'Activity_Certificate'].forEach(field => {
    if (field in body && body[field]) {
      if (!validator.isLength(body[field], { max: 255 })) {
        errors.push(`${field} must be no more than 255 characters`);
      }
    }
  });

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  next();
}

module.exports = validateInput;
