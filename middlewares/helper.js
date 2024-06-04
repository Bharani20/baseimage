// Crypto Imports
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const configs = require('../constant');
const axios = require('axios');
const dgram = require('dgram');

function generateSHA256(json) {
    // Convert the JSON object to a string
    const jsonString = JSON.stringify(json);

    // Create a SHA256 hash object
    const sha256Hash = crypto.createHash('sha256');

    // Update the hash object with the JSON string
    sha256Hash.update(jsonString);

    // Generate the SHA256 hash digest
    const hashDigest = sha256Hash.digest('hex');

    return hashDigest;
}

function convertTZ(date, tzString) {
    return new Date(
        (typeof date === 'string' ? new Date(date) : date).toLocaleString('en-US', {
            timeZone: tzString,
        })
    );
}
// Define udpTransport function
async function udpTransport(msg) {

    console.log('Into udp');
    console.log(msg)
    const currentTime = new Date();
    const formattedTime = convertTZ(currentTime, 'Africa/Sao_Tome');
    console.log(formattedTime)

    // Format for syslog
    const formattedMessage = formattedTime + ' My Security Logs ' + msg;
    console.log(formattedMessage);

    const fn = 'udpTransport';
    const message = Buffer.from(formattedMessage);
    const socket = dgram.createSocket('udp4');
    const bytesSocketCall1 = async function () {
        const bytesSocket1 = socket.send(
            message,
            0,
            message.length,
            configs.cdip.SPLUNKPORT,
            configs.cdip.SPLUNKIP,
            (err, bytes) => {
                if (err) {
                    console.log('Error While sending logs', err);
                }
                else {
                    console.log('Logs send successfully');
                }
            }
        );
    };
    await bytesSocketCall1();

    console.log(`[splunk-LOG] ${msg}`);
};

function compareSHA256(json, hashDigest) {
    const jsonString = JSON.stringify(json);
    const sha256Hash = crypto.createHash('sha256');
    sha256Hash.update(jsonString);
    const inputHashDigest = sha256Hash.digest('hex');
    return inputHashDigest === hashDigest;
}

async function updateJWTSecretKey(jwtData, nationalId) {
    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/updateJWTDetails`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "JWT_SECRET": JSON.stringify(jwtData),
            "NATIONAL_ID": nationalId
        },
    };

    try {
        // Make the request to the authentication service
        const response = await axios(options);

        console.log("updateJWTSecretKey Response")
        console.log(response)

        return response.data || null;
    } catch (error) {
        throw error
    }

}


async function postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length) {

    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/createLogging`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "PROJECT_ID": 1,
            "AUTH_ID": "",
            "DATE_TIME": date_time,
            "SOURCE_IP": sourceip,
            "TARGET_IP": "Auth Server",
            "USERID": userid,
            "URI": endpoint,
            "JWT_STATUS": jwt_status,
            "HTTP_STATUS": http_status,
            "PAYLOAD_SIZE": payload_length,
            "RESPONSE_TIME": response_time,
            "RESPONSE_SIZE": response_length,
            "TO_SPLUNK": 1,
            "PAYLOAD_METADATA": "",
            "RESPONSE_METADATA": ""
        }
    };
    console.log(options);
    try {
        // Make the request to the authentication service
        const response = await axios(options);
        console.log("posting logs to oracle server")
        console.log(response)
        return response.data[0] || null;
    } catch (error) {
        console.log(error)
        throw error
    }
}


async function postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification) 
{

    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/createUserLoginLogs`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "USER_NAME": userid,
            "DATE_TIME": date_time,
            "SOURCE_IP": sourceip,
            "ISOTP": isotp,
            "ISVERIFYOTP": isverifyotp,
            "ISUPDATEPUBLICKEY": isupdatepublickey,
            "ISJWT": isjwt,
            "JUSTIFICATION": justification
        }
    };
    console.log(options);
    try {
        // Make the request to the authentication service
        const response = await axios(options);
        console.log("posting user login logs to oracle server")
        console.log(response)
        return response.data[0] || null;
    } catch (error) {
        console.log(error)
        throw error
    }
}

async function getUserDetailsByID(nationalID) {
    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/getLoginDetails`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "NATIONAL_ID": nationalID
        },
    };

    try {
        // Make the request to the authentication service
        const response = await axios(options);
        console.log("getUserDetailsByID Response")
        console.log(response)

        return response.data[0] || null;
    } catch (error) {
        console.log(error)
        throw error
    }
}

async function getOTPHashDetails(nationalID) {

    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/getOTPVerification`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "NATIONAL_ID": nationalID
        },
    };

    try {
        // Make the request to the authentication service
        const response = await axios(options);

        console.log("getOTPHashDetails Response")
        console.log(response)

        return response.data[0] || null;
    } catch (error) {
        throw error
    }

}

function expired(expirationTimestamp) {
    const currentTimestamp = Date.now();
    return currentTimestamp > expirationTimestamp;
}

async function generateJwtToken(nationalId, time) {

    const JWTKEY = '5cec035537bf20697cec520fc0d9f8d7c874d414fb7b49b9a75a27d890943c00';
    //crypto.randomBytes(32).toString('hex');

    const expiresIn = time;

    const payload = { nationalId }; // Payload to be discussed and finalized. 

    const expirationTimestamp = Date.now() + 3 * 60 * 60 * 1000;

    const jwtData = {
        JWTKEY: JWTKEY,
        expirationTimestamp: expirationTimestamp
    };

    const isSecretUpdated = await updateJWTSecretKey(jwtData, nationalId);   // Save the JWTKEY in DB against the national id. 

    if (!isSecretUpdated) return null;

    const token = jwt.sign(payload, JWTKEY, { expiresIn });

    return token;
}

async function verifyToken(req, res, next) {
    const token = req.headers.authorization;

    const nationalId = req.body.national_id || null;
    var userDetails = await getUserDetailsByID(nationalId);
    var jwtSecret = userDetails["JWT_SECRET"] || null;
    var secretKey = JSON.parse(userDetails["JWT_SECRET"])["JWTKEY"] || null;
    var keyExpiry = JSON.parse(userDetails["JWT_SECRET"])["expirationTimestamp"] || null;
    var isExpired = expired(keyExpiry)

    if (!userDetails) {
        return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
    }

    if (!token) {
        return res.status(401).json({ error: true, message: 'Unauthorized - No token provided' });
    }

    if (isExpired) {
        return res.status(401).json({ error: true, message: 'Session timeout login agian.' });
    }

    // get Bearer token from Authorization header
    const authHeaders = token.split(' ');
    const jwtToken = authHeaders[1];

    jwt.verify(jwtToken, secretKey, (error, decoded) => {
        if (error) {
            return res.status(403).json({ error: true, message: 'Forbidden - Invalid token' });
        }
        req.user = decoded; // Attach decoded user information to the request
        next();
    });
}

function generateOTP() {
    // Generate a secure random 6-digit number
    const buffer = crypto.randomBytes(3); // 3 bytes = 24 bits
    const otp = buffer.readUIntBE(0, 3) % 1000000; // Ensure it's a 6-digit number
    return otp.toString().padStart(6, '0'); // Pad with leading zeros if needed
}

async function sendOTPViaSMS(data) {

    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'Date': new Date().toUTCString(),
    };

    const options = {
        url: `${configs.cdip.JAVA_URL}/newmysecurity/common/otp/send`,
        json: true,
        proxy: false,
        headers: headers,
        method: configs.cdip.POST_METHOD,
        data: data
    };

    console.log("OTP API Options")

    try {
        // Make the request to the authentication service
        const response = await axios(options);

        console.log("OTP API Response")

        console.log(response)

        // Handle the response from the authentication service
        if (response.error) {
            return false;
        } else {
            // Continue with the normal flow or handle the response accordingly
            // Do something with the response or send it back to the client
            return true;
        }
    } catch (error) {
        console.log("OTP API catch error")
        console.log(error)
        return false
    }

}

async function updateLoginDetailsWithOTP(nationalID, otpDetails) {
    const options = {
        url: `${configs.cdip.ORACLE_URL}/api/updateOTPDetails`,
        json: true,
        proxy: false,
        method: configs.cdip.POST_METHOD,
        data: {
            "OTP_DETAILS": JSON.stringify(otpDetails),
            "NATIONAL_ID": nationalID
        },
    };

    try {
        // Make the request to the authentication service
        const response = await axios(options);

        console.log("updateLoginDetailsWithOTP Response")
        console.log(response)

        return response.data || null;
    } catch (error) {
        throw error
    }

}

module.exports = { generateSHA256, compareSHA256, generateJwtToken, verifyToken, generateOTP, sendOTPViaSMS, getUserDetailsByID, updateLoginDetailsWithOTP, getOTPHashDetails, udpTransport, postlogs, expired,postuserlogs};


