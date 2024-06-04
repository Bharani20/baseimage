// routes/auth.js
const express = require('express');
const router = express.Router();
const configs = require("../constant");
const axios = require('axios');


// Custom Imports
const { generateSHA256, compareSHA256, generateJwtToken, generateOTP, sendOTPViaSMS, getUserDetailsByID, updateLoginDetailsWithOTP, getOTPHashDetails, udpTransport, postlogs, expired, postuserlogs } = require('../middlewares/helper');

// Crypto Imports
const crypto = require('crypto');
const JSEncrypt = require('jsencrypt');
var SHA512 = require("crypto-js/sha512");

// Ping route
router.get('/', (req, res) => {
    console.log("Auth server Route is accessable")
    res.send('Hello, World! Auth server is up and running');
});

router.post('/', (req, res) => {
    console.log(req.headers);
    console.log("Source IP - ", req.headers['x-forwarded-for']);
    res.send('Hello, World! Auth server is up and running');
});

const https = require('https');
const querystring = require('querystring');

// -------Global variables for posting respective logs-------------------------- //

// var new_date;
// var date_time;
// var sourceip;
// var userid;
// var endpoint;
// var jwt_status = 'Not applicable';
// var http_status;
// var payload_length;
// var response_time;
// var response_length;
// var starttime;
// var isotp;
// var isverifyotp;
// var isupdatepublickey;
// var isjwt;
// var justification;
// var endtime;

// -------scope variables for posting respective logs-------------------------- //


router.post('/verifyUserHash', async (req, res) => {
    console.log("inside verifyUserHash from Auth Service");
    try {
        console.log("inside verifyUserHash from Auth Service")
        const nationalID = req.body.national_id || null;

        // -------Common info's for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // userid = nationalID;
        // endpoint = req.url;
        // starttime = Date.now();
        // isotp = 0;
        // isverifyotp = 0;
        // isupdatepublickey = 0;
        // isjwt = 0;

        // -------scope variables for posting respective logs-------------------------- //

        const userDetails = await getUserDetailsByID(nationalID);
        // endtime = Date.now();
        console.log("Inside user hash and oracle call response")
        console.log(userDetails)

        if (!userDetails) {

            // ---------- normal logging to log table--------------------- //
            // http_status = "404 User Not Found";
            // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8');
            // response_length = 0;
            // response_time = endtime - starttime;
            // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
            // console.log(logresponse);
            // ---------- normal logging to log table--------------------- //

            // ------------------ failed userlogin logs -------------------- //
            // justification = 'No details exist for the mentioned national ID';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //

            return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
        }
        const storedHash = userDetails.hash;
        const phoneNumber = "+" + userDetails.MOBEXT + "-" + userDetails.PHONE_NUMBER;

        const isMatch = compareSHA256({
            'national_id': nationalID,
            'phone_number': req.body.phone_number
        }, generateSHA256({
            'national_id': userDetails.NATIONAL_ID,
            'phone_number': userDetails.MOBEXT + userDetails.PHONE_NUMBER
        }));

        console.log("JSON from mobile")
        console.log("nationalID")
        console.log(nationalID)
        console.log("req.body.phone_number")
        console.log(req.body.phone_number)

        console.log("JSON from Oracle DB")
        console.log("nationalID")
        console.log(userDetails.NATIONAL_ID)
        console.log("req.body.phone_number")
        console.log(userDetails.MOBEXT + userDetails.PHONE_NUMBER)

        console.log("Hash verification result after change")
        console.log(isMatch)

        if (!isMatch || !phoneNumber) {

            // udpTransport(`Hash Verification failed for: ${nationalID}`);
            // http_status = "401 Unauthorised Hash Verification Failed";
            // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8');
            // response_length = 0;
            // response_time = endtime - starttime;
            // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
            // console.log(logresponse);

            // ------------------ failed userlogin logs -------------------- //

            // if (!phoneNumber) {
            //     justification = 'Hash Verification failed since there is no phonenumber for the user';
            // } else if (!isMatch) {
            //     justification = 'Hash Verification failed because of the phonenumber entered by the user and the phone number in db or not matched or there me bay duplicate entries for the user';
            // }
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }

            // ------------------ failed userlogin logs -------------------- //  

            return res.status(401).json({ error: 'Hash verification failed' });
        }

        const generatedOTP = generateOTP();
        const expirationTimestamp = Date.now() + 2 * 60 * 1000;
        const otpDetails = {
            otp: generatedOTP,
            expirationTimestamp: expirationTimestamp
        };

        const isUpdateSuccessful = await updateLoginDetailsWithOTP(nationalID, otpDetails);

        if (!isUpdateSuccessful) {

            // ------------------ failed userlogin logs -------------------- //

            // justification = 'User not found while updating otp details';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //

            return res.status(404).send("User not found");
        }

        const cleanedPhoneNumber = phoneNumber.replace(/\D/g, '');

        const otpResponse = await sendOTPViaSMS({
            "oTPMessageDTO": {
                "oTPCode": generatedOTP,
                "mobileNumber": cleanedPhoneNumber  // "966546084701"
            }
        });

        console.log("OTP API Response")
        console.log(otpResponse)

        if (!otpResponse) {
            // ------------------ failed userlogin logs -------------------- //  
            // justification = 'Error sending OTP check the sms gateway or java api'
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //  

            return res.status(401).send({ OTP: false, message: "Error sending OTP" });
        }
        // http_status = "200 Ok OTP Sent Successfully";
        // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8');
        // response_length = 0;
        // response_time = endtime - starttime;
        // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
        // console.log(logresponse);
        return res.status(200).send({ OTP: true, message: "OTP sent successfully", phonenumber: cleanedPhoneNumber });

    } catch (error) {
        console.log(error)
        // http_status = "500 error An error occurred while verifying the user hash.";
        // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8');
        // response_length = 0;
        // response_time = 0;
        // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
        // console.log(logresponse);

        // ------------------ failed userlogin logs -------------------- //
        // justification = 'An error occurred while verifying the user hash, check the payload or oc';
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //
        return res.status(500).json({ error: 'An error occurred while verifying the user hash.' });
    }
});

router.post('/updatePublicKey', async (req, res) => {
    try {
        const { public_key, national_id } = req.body;
        const userOTPHash = req.body.hash || null;

        // -------common info's for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en-US', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // console.log("date-", date_time);
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // userid = national_id;
        // endpoint = '/verifyOTP';
        // starttime = Date.now();
        // isotp = 1;
        // isverifyotp = 1;
        // isupdatepublickey = 0;
        // isjwt = 0;

        // -------scope variables for posting respective logs-------------------------- //

        if (userOTPHash) {
            const OTPresult = await getOTPHashDetails(national_id);
            if (OTPresult) {
                const dbOTPHash = OTPresult.OTP_VERIFY_HASH;
                if (userOTPHash === dbOTPHash) {
                    const options = {
                        url: `${configs.cdip.ORACLE_URL}/api/updateLoginDetails`,
                        json: true,
                        proxy: false,
                        method: configs.cdip.POST_METHOD,
                        data: {
                            "PUBLIC_KEY": public_key,
                            "NATIONAL_ID": national_id
                        },
                    };

                    try {
                        // Make the request to the authentication service
                        const response = await axios(options);
                        if (response) {
                            res.status(200).send("Updated Successfully");
                        } else {
                            // ------------------ failed userlogin logs -------------------- //
                            // justification = 'User not found in oracle db while updating otphash details';
                            // try {
                            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                            //     console.log("User login logs posted Successfully");
                            // } catch (err) {
                            //     console.log(err);
                            // }
                            // ------------------ failed userlogin logs -------------------- //
                            res.status(404).send("User not found");
                        }
                    } catch (error) {
                        throw error
                    }
                } else {
                    // ------------------ failed userlogin logs -------------------- //
                    // justification = 'Wrong Otp Hash from the user';
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //
                    res.status(401).send("UnAuthorized Request");
                }
            } else {
                // ------------------ failed userlogin logs -------------------- //
                // justification = 'No OTP Hash details found for this user';
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //
                res.status(401).send("UnAuthorized Request");
            }
        } else {
            // ------------------ failed userlogin logs -------------------- //

            // justification = 'No Otp hash received from the user';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //
            res.status(401).send("UnAuthorized Request");
        }
    } catch (error) {
        // ------------------ failed userlogin logs -------------------- //

        // justification = 'An error occurred while updating the public key check the java server or java Api';
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //
        res.status(500).json({ error: 'An error occurred while updating the public key.' });
    }
});

// Verify signed id and issue challenge
router.post('/issueChallenge', async (req, res) => {
    try {
        const signedId = req.body.signed_id || null;
        const nationalId = req.body.national_id || null;
        const userOTPHash = req.body.hash || null;

        // -------scope variables for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en-US', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // console.log("date-", date_time);
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // userid = nationalId;
        // endpoint = '/verifyOTP';
        // starttime = Date.now();
        // isotp = 1;
        // isverifyotp = 1;
        // isupdatepublickey = 1;
        // isjwt = 0;

        // -------scope variables for posting respective logs-------------------------- //

        const OTPresult = await getOTPHashDetails(nationalId);

        if (OTPresult) {
            const dbOTPHash = OTPresult.OTP_VERIFY_HASH;
            if (userOTPHash === dbOTPHash) {
                const userDetails = await getUserDetailsByID(nationalId);

                if (!userDetails) {

                    // ------------------ failed userlogin logs -------------------- //

                    // justification = 'No details exist for the mentioned national ID at issue challenge step';
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //

                    return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
                }
                const user = userDetails;
                const publicKey = `-----BEGIN PUBLIC KEY-----
                        ${user['PUBLIC_KEY']}
                        -----END PUBLIC KEY-----`

                const verify = new JSEncrypt();
                verify.setPublicKey(publicKey);
                const isVerified = verify.verify(nationalId, signedId, SHA512);

                if (isVerified) {
                    // Signed gov id verified. Send it back with a challenge
                    const encrypt = new JSEncrypt();
                    encrypt.setPublicKey(publicKey);
                    const encryptedChallenge = encrypt.encrypt(configs.cdip.CHALLENGE); //crypto.randomBytes(32).toString('hex')

                    res.status(201).send(encryptedChallenge);
                } else {
                    // ------------------ failed userlogin logs -------------------- //

                    // justification = 'Signed ID verification failed at issue challenge step';
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //
                    res.status(200).json({
                        error: true,
                        data: "Signed ID verification failed"
                    });
                }

            } else {

                // ------------------ failed userlogin logs -------------------- //
                // justification = 'The hash entered by the user does not matches with the hash in the db';
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //
                res.status(401).send("UnAuthorized Request");
            }
        } else {
            // ------------------ failed userlogin logs -------------------- //

            // justification = 'No hash details exists for the user in the db';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //
            res.status(401).send("UnAuthorized Request");
        }
    } catch (error) {
        // ------------------ failed userlogin logs -------------------- //

        // justification = 'An error occurred while issuing the challenge check java server or java api';
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //
        res.status(500).json({ error: 'An error occurred while issuing the challenge.' });
    }
});

router.post('/validateSignedChallenge', async (req, res) => {
    try {
        const signedChallenge = req.body.signed_challenge || null;
        const nationalId = req.body.national_id || null;
        const userOTPHash = req.body.hash || null;

        // -------scope variables for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en-US', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // console.log("date-", date_time);
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // userid = nationalId;
        // endpoint = req.url;
        // starttime = Date.now();
        // isotp = 1;
        // isverifyotp = 1;
        // isupdatepublickey = 1;
        // isjwt = 0;

        // -------scope variables for posting respective logs-------------------------- //

        if (userOTPHash) {
            const OTPresult = await getOTPHashDetails(nationalId);
            if (OTPresult) {
                const dbOTPHash = OTPresult.OTP_VERIFY_HASH;
                if (userOTPHash === dbOTPHash) {
                    const userDetails = await getUserDetailsByID(nationalId);
                    if (!userDetails) {
                        // ------------------ failed userlogin logs -------------------- //

                        // justification = 'No details exist for the mentioned national ID at issue challenge step';
                        // try {
                        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                        //     console.log("User login logs posted Successfully");
                        // } catch (err) {
                        //     console.log(err);
                        // }
                        // ------------------ failed userlogin logs -------------------- //
                        return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
                    }
                    const user = userDetails;

                    const publicKey = `-----BEGIN PUBLIC KEY-----
                            ${user.PUBLIC_KEY}
                            -----END PUBLIC KEY-----`;

                    const verify = new JSEncrypt();
                    verify.setPublicKey(publicKey);
                    const isVerified = verify.verify(configs.cdip.CHALLENGE, signedChallenge, SHA512);

                    if (isVerified) {
                        const token = await generateJwtToken(nationalId, configs.cdip.JWTSESSION)
                        udpTransport(`User Loggedin Successfully: ${nationalId}`);
                        res.status(201).send(token);
                    }
                    else {
                        // ------------------ failed userlogin logs -------------------- //

                        // justification = 'Signed challenge verification failed at validateissue challenge step';
                        // try {
                        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                        //     console.log("User login logs posted Successfully");
                        // } catch (err) {
                        //     console.log(err);
                        // }
                        // ------------------ failed userlogin logs -------------------- //
                        res.status(401).json({
                            error: true,
                            data: "Signed challenge verification failed"
                        });
                    }

                } else {
                    // ------------------ failed userlogin logs -------------------- //

                    // justification = 'The hash entered by the user does not matches with the hash in the db';
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //
                    res.status(401).send("UnAuthorized Request");
                }
            } else {
                // ------------------ failed userlogin logs -------------------- //

                // justification = 'No hash details exists for the user in the db';
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //
                res.status(401).send("UnAuthorized Request");
            }
        } else {
            // ------------------ failed userlogin logs -------------------- //

            // justification = 'No hash details entered by the user';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //
            res.status(401).send("UnAuthorized Request");
        }

    } catch (error) {
        // ------------------ failed userlogin logs -------------------- //

        // justification = 'An error occurred while validating the signed challenge check java api or java server';
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //
        res.status(500).json({ error: 'An error occurred while validating the signed challenge.' });
    }
});

router.post('/validateEmployee', async (req, res) => {
    try {
        const username = req.body.username || null;
        const password = req.body.password || null;

        // -------scope variables for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en-US', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // console.log("date-", date_time);
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // console.log("Headers - ", req.headers);
        // userid = username;
        // endpoint = '/validateEmployee';
        // isotp = 0;
        // isverifyotp = 0;
        // isupdatepublickey = 0;
        // isjwt = 0;

        // -------scope variables for posting respective logs-------------------------- //

        const headers = {
            //   'Authorization': req.headers.authorization,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache',
            'Date': new Date().toUTCString(),
            //  'x-signature': req.headers['x-signature'],
        };
        const options = {
            url: `${configs.cdip.JAVA_URL}/newmysecurity/common/login`,
            json: true,
            proxy: false,
            headers: headers,
            method: configs.cdip.POST_METHOD,
            data: {
                "id": username,
                "value": password
            }
        };
        // var starttime = Date.now();
        try {
            // Make the request to the authentication service
            console.log("Validate Emp options")
            const response = await axios(options);
            // var endtime = Date.now();
            console.log("Validate emp Resp")
            // console.log(response)

            // Handle the response from the authentication service
            if (response.error) {
                // sending logs to oracle DB 
                // http_status = "500 Error";
                // payload_length = JSON.stringify(req.body).length;
                // response_length = 0;
                // response_time = endtime - starttime;
                // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
                // console.log(logresponse);


                // ------------------ failed userlogin logs -------------------- //

                // justification = 'Error from java api' + JSON.stringify(response.error);
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //

                res.status(500).send(response.error);
            } else if (response.data.loginSucess) {
                const userDetails = await getUserDetailsByID(username);

                if (!userDetails) {
                    // udpTransport(`Authentication failed for user: ${username}`);
                    // ------------------ failed userlogin logs -------------------- //

                    // justification = "No details exists for the mentioned National ID";
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //
                    return res.status(404).json({
                        error: "No details exists for the mentioned National ID"
                    });
                }

                const phoneNumber = "+" + userDetails.MOBEXT + "-" + userDetails.PHONE_NUMBER;

                // Continue with the normal flow or handle the response accordingly
                // User verified, Send OTP
                const generatedOTP = generateOTP();
                const expirationTimestamp = Date.now() + 2 * 60 * 1000;
                const otpDetails = {
                    otp: generatedOTP,
                    expirationTimestamp: expirationTimestamp
                };

                const isUpdateSuccessful = await updateLoginDetailsWithOTP(username, otpDetails);
                if (!isUpdateSuccessful) {
                    // ------------------ failed userlogin logs -------------------- //

                    // justification = 'User not found while updating otp details';
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- //
                    return res.status(404).send("User not found");
                }

                const cleanedPhoneNumber = phoneNumber.replace(/\D/g, '');
                const otpResponse = await sendOTPViaSMS({
                    "oTPMessageDTO": {
                        "oTPCode": generatedOTP,
                        "mobileNumber": cleanedPhoneNumber
                    }
                });

                if (!otpResponse) {

                    // ------------------ failed userlogin logs -------------------- // 

                    // justification = 'Error sending OTP check the sms gateway or java api'
                    // try {
                    //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                    //     console.log("User login logs posted Successfully");
                    // } catch (err) {
                    //     console.log(err);
                    // }
                    // ------------------ failed userlogin logs -------------------- // 

                    return res.status(200).send({ OTP: false, message: "OTP verification failed. Allowing for testing purposes." });
                }
                // udpTransport(`OTP sent successfully: ${username}`);
                // http_status = "200 Ok Otp Send Successfully";
                // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8') || 0;
                // response_length = Buffer.byteLength(JSON.stringify(response.data), 'utf-8') || 0;
                // response_time = endtime - starttime;
                // try {
                //     const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
                //     console.log(logresponse);
                // } catch (err) {
                //     console.log("Could not send logs");
                // }
                res.status(200).send({ OTP: true, message: "OTP sent successfully", data: response.data, phonenumber: cleanedPhoneNumber });
                //Send to client
            } else {
                // http_status = "401 Unauthorized";
                // payload_length = JSON.stringify(req.body).length;
                // response_length = JSON.stringify(response.data).length;
                // response_time = endtime - starttime;
                // try {
                //     const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
                //     console.log(logresponse);
                // } catch (err) {
                //     console.log("Could not send logs");
                // }

                // ------------------ failed userlogin logs commented invalid username -------------------- // 

                // console.log("JSON-error - ", JSON.stringify(response.data));
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- // 
                res.status(401).send(response.data);
            }
        } catch (error) {
            // var endtime = Date.now();
            console.log(error)
            // Handle errors
            if (error["response"]) {
                // http_status = error.response.status;
                // payload_length = JSON.stringify(req.body).length;
                // response_length = 0;
                // response_time = endtime - starttime;
                // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
                // console.log(logresponse);

                // ------------------ failed userlogin logs -------------------- // 

                // justification = 'Error from java Api'
                // console.log(JSON.stringify(error.response.data.error))
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //

                res.status(error.response.status).json(error.response.data.error);
            }
            else {
                // udpTransport(`Internal Server Error: ${username}`);
                // endtime = Date.now();
                // console.log(error);
                // http_status = "500 Error";
                // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8') || 0;
                // response_length = 0;
                // response_time = endtime - starttime;
                // try {
                //     const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
                //     console.log(logresponse);
                // } catch (err) {
                //     console.log("Could not send logs");
                // }

                // ------------------ failed userlogin logs -------------------- // 
                // justification = "Internal Server Error"
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //
                res.status(500).send("Internal Server Error")
            }
        }
    } catch (error) {
        console.log(error);
        // http_status = "500 Error";
        // payload_length = JSON.stringify(req.body).length;
        // response_length = 0;
        // response_time = 0;
        // try {
        //     const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
        //     console.log(logresponse);
        // } catch (err) {
        //     console.log("Could not send logs");
        // }

        // ------------------ failed userlogin logs -------------------- // 

        // justification = "An error occurred while entering validateEmployee Endpoint"
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //

        res.status(500).json({ message: 'An error occurred ', error: error });

    }
});

router.post('/verifyOTP', async (req, res) => {

    try {
        const nationalId = req.body.national_id || null;
        const userOTP = req.body.otp || null;

        // -------common info's for posting respective logs-------------------------- //

        // new_date = new Date().toLocaleString('en-US', { timeZone: 'Asia/Riyadh' });
        // date_time = new Date(new_date).toISOString();
        // console.log("date-", date_time);
        // sourceip = req.ip.replace(/^::ffff:/, '');
        // userid = nationalId;
        // endpoint = '/verifyOTP';
        // jwt_status = 'Not applicable';
        // starttime = Date.now();
        // isotp = 1;
        // isverifyotp = 0;
        // isupdatepublickey = 0;
        // isjwt = 0;

        // -------common info's for posting respective logs-------------------------- //


        const userDetails = await getUserDetailsByID(nationalId);
        // var endtime = Date.now();
        if (!userDetails) {
            // ---------- normal logging to log table--------------------- //
            // http_status = "404 User Not Found";
            // payload_length = Buffer.byteLength(JSON.stringify(req.body), 'utf-8');
            // response_length = 0;
            // response_time = endtime - starttime;
            // const logresponse = await postlogs(date_time, sourceip, userid, endpoint, jwt_status, http_status, payload_length, response_time, response_length);
            // console.log(logresponse);
            // ---------- normal logging to log table--------------------- //

            // ------------------ failed userlogin logs -------------------- //

            // justification = 'No details exist for the mentioned national ID';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //
            return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
        }
        const user = userDetails;
        const otpDetails = user.OTP_DETAILS
        var dbOTP = JSON.parse(user["OTP_DETAILS"])["otp"] || null;
        var keyExpiry = JSON.parse(user["OTP_DETAILS"])["expirationTimestamp"] || null;


        if (userOTP == dbOTP) {
            // Checking Expiry Time for OTP
            if (!expired(keyExpiry)) {

                // Generate a OTP verification token and send it back
                const hash = generateSHA256({
                    'dbOTP': dbOTP,
                    'userOTP': userOTP,
                    'nationalId': nationalId
                });
                // Save this hash to DB 
                const options = {
                    url: `${configs.cdip.ORACLE_URL}/api/updateOTPHashDetails`,
                    json: true,
                    proxy: false,
                    method: configs.cdip.POST_METHOD,
                    data: {
                        "OTP_VERIFY_HASH": hash,
                        "NATIONAL_ID": nationalId
                    },
                };

                try {
                    // Make the request to the authentication service
                    const response = await axios(options);
                    if (response) {
                        res.status(200).send({
                            status: true,
                            hash: hash
                        })
                    } else {
                        res.status(404).send("User not found");
                    }
                } catch (error) {
                    throw error
                }
            }
            else {
                // ------------------ failed userlogin logs -------------------- //

                // justification = 'The OTP entered by the user is expired';
                // try {
                //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
                //     console.log("User login logs posted Successfully");
                // } catch (err) {
                //     console.log(err);
                // }
                // ------------------ failed userlogin logs -------------------- //
                res.status(500).json({ error: 'OTP expired please try again' })
            }
        }
        else {
            // ------------------ failed userlogin logs -------------------- //

            // justification = 'The OTP Entered by the user is wrong';
            // try {
            //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
            //     console.log("User login logs posted Successfully");
            // } catch (err) {
            //     console.log(err);
            // }
            // ------------------ failed userlogin logs -------------------- //
            res.status(401).send(false);
        }
    } catch (error) {
        // ------------------ failed userlogin logs -------------------- //

        // justification = 'An Internal Server Occured While Verifying OTP may be Java service down or Java API Down';
        // try {
        //     const userlogs = await postuserlogs(userid, date_time, sourceip, isotp, isverifyotp, isupdatepublickey, isjwt, justification);
        //     console.log("User login logs posted Successfully");
        // } catch (err) {
        //     console.log(err);
        // }
        // ------------------ failed userlogin logs -------------------- //
        res.status(500).json({ error: 'An error occurred while validating the signed challenge.' });
    }
});

module.exports = router;
