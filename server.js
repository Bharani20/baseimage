// Application Imports
const express = require('express');
const bodyParser = require("body-parser");
global.navigator = { appName: 'nodejs' };
global.window = {};

// Custom Imports
const configs = require("./constant");

// Constants
const port = configs.cdip.PORT;

const app = express();
app.use(express.json());

// Middleware
app.use(bodyParser.json());


// Routes
const authRoute = require('./routes/auth');
const validatorRoute = require('./routes/validator');

app.use('/', authRoute);
app.use('/proxy', validatorRoute);

// Error handling middleware
app.use((err, req, res, next) => {
    res.status(500).send('Something went wrong!');
});

// 404 Not Found middleware
app.use((req, res) => {
    res.status(404).send('404 Not Found');
});

// Start the server
app.listen(port, () => {
    console.log("Auth Sever Running")
});
