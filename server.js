const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
/*/ 
 *  ⛔ If you get a TextEncoder not Defined Error, you need to copy this
 *  ⛔ in the beginning of the file that gives the error:
 *  ⛔ const {TextEncoder, TextDecoder} = require('util');
/*/
const { MongoClient } = require('mongodb');


/*/
 *  ❗ Database Information - Change this if yours is different. ❗
/*/
const url = "mongodb://localhost:27017/";
const client = new MongoClient(url);
const dbName = "UserDB";
const dbCollection = "users";

client.connect().then(
    r => console.log("Connected to mongodb at " + url + " with response " + r + "\n")
);

const server = express();


/*/
 *  The user's session (cookie).
/*/
server.use(session({
    secret: '123456',
    resave: true,
    saveUninitialized: true,
}));
server.use(express.urlencoded({ extended: true }));
server.use(express.json());


/*/
 *  Load the initial login page that has the form.
/*/
server.get('/', function (request, response) {
    response.sendFile(path.join(__dirname + '/login.html'));
});


/*/
 *  Log Session Info  -- Session Object should be fully initialized.
/*/
const logLoginSessionInfo = (sessionObject) => {
    console.log(
        "----------------------------------------------------------------------\n" +
        "Session ID: " + sessionObject.id + "\n" +
        "----------------------------------------------------------------------\n" +
        "Username: " + (sessionObject.user ? sessionObject.user : "No Username Provided") + "\n" +
        "Login Status: " + sessionObject.loggedin + "\n" +
        "Incorrect Login Attempts: " + sessionObject.incorrectLoginAttempts + "\n" +
        "Locked Out: " + sessionObject.lockedOut + "\n" +
        "----------------------------------------------------------------------\n"
    );
}


/*/
 *  Respond with the results of the authentication process done by post('/authenticate')
/*/
const sendAuthenticationResults = (response, sessionObject, log) => {
    response.send({
        "loginStatus": sessionObject.loggedin,
        "incorrectAttempts": sessionObject.incorrectLoginAttempts,
        "lockedOut": sessionObject.lockedOut
    });
    response.end();
    if (log) logLoginSessionInfo(sessionObject);
}


/*/
 *  This accepts the post from the login for, and preforms the
 *  password check against the result from the mongodb.
 *
 *  Request Format:  -- If either, or, both of these fields are missing, it only responds with 400 [Bad Request].
 *  {
 *      "username" : "theUsername",
 *      "password" : "thePassword"
 *  }
 *
 *  Response Format:
 *  {
 *      "loginStatus"       : boolean,  -- whether the user is logged in or not
 *      "incorrectAttempts" : integer,  -- how many times they failed logging in
 *      "lockedOut"         : boolean   -- whether the user's session is locked or not
 *  }
/*/
server.post('/authenticate', function (request, response) {

    let sessionInfo = request.session;

    const username = request.body.username;
    const password = request.body.password;

    if (sessionInfo.infoSet == null) {
        sessionInfo.infoSet = true;
        sessionInfo.incorrectLoginAttempts = 0;
        sessionInfo.loggedin = false;
        sessionInfo.lockedOut = false;
        sessionInfo.id = request.sessionID;
    }

    sessionInfo.user = (username ? username : "");

    if (!username || !password) {
        response.sendStatus(400);
        logLoginSessionInfo(sessionInfo);
    }

    if (username && password && !request.session.lockedOut) {
        // find username in dbCollection in dbName and get the username,password object for that user
        client.db(dbName).collection(dbCollection).find({ 'username': username }).toArray(function (err_db, result) {

            if (err_db) throw err_db;

            if (!result[0]) {
                // Username does not exist: this counts as a bad login attempt.
                sessionInfo.incorrectLoginAttempts++;
                if (sessionInfo.incorrectLoginAttempts === 3) {
                    sessionInfo.lockedOut = true;
                }
                sendAuthenticationResults(response, sessionInfo, true);
            } else {
                // Hash check the inputted password against the one in the database.
                bcrypt.compare(password, result[0]['password'], function (err_hash, successful_login) {

                    if (err_hash) throw err_hash;

                    if (successful_login) {
                        sessionInfo.user = username;
                        sessionInfo.loggedin = true;
                        sessionInfo.incorrectLoginAttempts = 0;
                    } else {
                        sessionInfo.incorrectLoginAttempts++;
                        if (sessionInfo.incorrectLoginAttempts === 3) {
                            sessionInfo.lockedOut = true;
                        }
                    }
                    sendAuthenticationResults(response, sessionInfo, true);
                });
            }
        });
    } else if (username && password) {
        // Should only get here if locked out
        sendAuthenticationResults(response, sessionInfo, true);
    }
});


/*/
 *  Get to find out if a user's session cookie is authenticated.
 *
 *  Response Format:
 *  ----------------
 *  {
 *      "loginStatus" : boolean  -- whether the user is logged in or not
 *  }
/*/
server.get('/authenticate', function (request, response) {
    if (request.session.loggedin) {
        console.log(
            "----------------------------------------------------------------------\n" +
            "Auto-Redirected: " + request.session.user + "\n" +
            "----------------------------------------------------------------------\n"
        );
        response.send({ "loginStatus": true });
    } else {
        response.send({ "loginStatus": false });
    }
    response.end();
});


/*/
 *  Post to create account
 *
 *  Request Format:
 *  {
 *      "email"     : "theEmail"   ,
 *      "username"  : "theUsername",
 *      "password"  : "thePassword"
 *  }
 * 
 *  Response Format:
 *  ----------------
 *  {
 *      "emailInUse"     : boolean  -- whether the email is already in use
 *      "usernameInUse"  : boolean  -- whether the username is already in use
 *      "createdAccount" : boolean  -- whether the account was created successfully
 *  }
/*/
server.post('/create-account', function (request, response) {

    let sessionInfo = request.session;

    const email = request.body.email;
    const username = request.body.username;
    const password = request.body.password;

    let res = {
        "emailInUse": false,
        "usernameInUse": false,
        "accountCreated": false
    };

    // Send status code 400 [Bad Request] if not all information was provided
    if (!email || !username || !password) {
        response.sendStatus(400);
    } else {

        const saltRounds = 10;

        // Generate a salt and then hash the password with bcrypt
        bcrypt.genSalt(saltRounds, function (err_salt, salt) {

            if (err_salt) throw err_salt;

            bcrypt.hash(password, salt, function (err_hash, hash) {

                if (err_hash) throw err_hash;

                // Check if email already exists
                client.db(dbName).collection(dbCollection).find({ 'email': email }).toArray(function (err_findEmail, result) {

                    if (err_findEmail) throw err_findEmail;

                    if (result[0]) {
                        res['emailInUse'] = true;
                        response.send(res);
                    } else {

                        // Check if username already exists
                        client.db(dbName).collection(dbCollection).find({ 'username': username }).toArray(function (err_findUser, result) {

                            if (err_findUser) throw err_findUser;

                            if (result[0]) {
                                res['usernameInUse'] = true;
                                response.send(res);
                            } else {

                                const user = {
                                    "email": email,
                                    "username": username,
                                    "password": hash
                                }

                                // Insert the new user into the database
                                client.db(dbName).collection(dbCollection).insertOne(user, function (err_insert, result) {

                                    if (err_insert) throw err_insert;

                                    if (result) {
                                        res['accountCreated'] = true;
                                        console.log(
                                            "----------------------------------------------------------------------\n" +
                                            "Added user " + username + ", with email " + email + " to the database. 👍\n" +
                                            "----------------------------------------------------------------------\n"
                                        );
                                        sessionInfo.loggedin = true;
                                        sessionInfo.user = username;
                                    }
                                    response.send(res);
                                });
                            }
                        });
                    }
                });
            });
        });
    }
});


/*/
 *  This is the user's home page: they should only get
 *  here if they are logged in.
/*/
server.get('/home', function (request, response) {
    if (request.session.loggedin) {
        response.send('<h1>Hey there ' + request.session.user + ', you are now logged in. ✅</h1>');
    } else {
        response.redirect('http://localhost:8080/');
    }
    response.end();
});


server.listen(8080);