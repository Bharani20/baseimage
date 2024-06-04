const mongoose = require('mongoose');

// // Define User model
const nodeADUserSchema = new mongoose.Schema({
    mobile_number: String,
    national_id: String,
    badgeNumber: Number,
    suffix: String,
    dep_relation: String,
    date_of_birth: String,
    applicant_name: String,
    email_id: String,
    active_flag: Boolean
    // ... other properties if any
});

