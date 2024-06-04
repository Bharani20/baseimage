// routes/index.js
const express = require('express');
const router = express.Router();
const configs = require("../constant");
const { verifyToken } = require('../middlewares/helper');
const crypto = require('crypto');
const JSEncrypt = require('jsencrypt');
var SHA512 = require("crypto-js/sha512");
const { getUserDetailsByID } = require('../middlewares/helper');


// Validate Request // verifyToken
router.post('/validateRequest', verifyToken,  async (req, res) => {
    try {
        const reqBody = req.body;
        const nationalId = req.body.national_id;
        const signedPayload = req.headers['x-signature'];
        const userDetails = await getUserDetailsByID(nationalId);

        if (!userDetails) {
            return res.status(404).json({ error: 'No details exist for the mentioned national ID' });
        }
        const user = userDetails;
        const publicKey = `-----BEGIN PUBLIC KEY-----
                ${user.PUBLIC_KEY}
                -----END PUBLIC KEY-----`;

        const verify = new JSEncrypt();
        verify.setPublicKey(publicKey);
        const isVerified = verify.verify(reqBody, signedPayload, SHA512);

        if (isVerified) {
            res.status(201).send(true);
        }
        else {
            res.status(201).send(true);
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ error: true, message: 'Internal Server Error' });
    }
});

module.exports = router;
