/*/ 
 * Express server for a basic login application.
/*/

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
const sanitize = require('mongo-sanitize');


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


/*/
 *  The user's session (cookie).
/*/
const server = express();
const LOGINTIMEOUTSECONDS = 60;
server.use(session({
    secret: '123456',
    resave: true,
    saveUninitialized: true,
    cookie: {maxAge: LOGINTIMEOUTSECONDS * 1000}
}));
server.use(express.urlencoded({ extended: true }));
server.use(express.json());


/*/
 *  Load the initial login page that has the form.
/*/
server.get('/', (_, response) => {
    response.sendFile(path.join(__dirname + '/login.html'));
});


/*/
 *  Send the script for checking if the user is authenticated and/or if they have timed-out.
/*/
server.get('/auth_guard.js', (_, response) => {
    response.sendFile(path.join(__dirname + '/auth_guard.js'));
});


/*/
 *  Increment a user's incorrectLoginAttempts and lock them out if those attempts are greater than 2
/*/
const punishBadLogin = (userObject) => {

    const queryFilter = { "username": userObject.username };

    const incorrectLoginAttempts = userObject['incorrectLoginAttempts'] + 1;

    let updateFilter = {};

    if (incorrectLoginAttempts < 3) {
        updateFilter = { "$inc": { "incorrectLoginAttempts": 1 }, "$set": { "lastIncorrectAttemptTime": Date.now() } }
    } else if (incorrectLoginAttempts === 3) {
        updateFilter = { "$inc": { "incorrectLoginAttempts": 1 }, "$set": { "lockOutTime": Date.now() } };
    } // Should further incorrect logins make update the lockOut time?

    // Increment the incorrectLoginAttempts field in the database.
    client.db(dbName).collection(dbCollection).updateOne(queryFilter, updateFilter, (err_insert, result) => {

        if (err_insert) throw err_insert;

        console.log(
            "----------------------------------------------------------------------\n" +
            "User " + userObject.username + ", has attempted to login incorrectly " + incorrectLoginAttempts + " times.❗\n" +
            "----------------------------------------------------------------------\n"
        );

        return result;
    });
}


/*/
 *  Remove the lockOut and incorrectLoginAttempts from a user
/*/
const resetLockOut = (username) => {

    const queryFilter = { "username": username };
    const updateFilter = { "$set": { "lockOutTime": 0, "incorrectLoginAttempts": 0, "lastIncorrectAttemptTime": 0 } };

    // Increment the incorrectLoginAttempts field in the database.
    client.db(dbName).collection(dbCollection).updateOne(queryFilter, updateFilter, (err_insert, result) => {

        if (err_insert) throw err_insert

        else {
            console.log(
                "----------------------------------------------------------------------\n" +
                "User " + username + ", has had their lockOutTime and incorrectLoginAttempts reset.\n" +
                "----------------------------------------------------------------------\n"
            );
            return result;
        }

    });
}


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
        "lockedOut": sessionObject.lockedOut,
        "unknownUsername": sessionObject.unknownUsername
    });
    if (log) logLoginSessionInfo(sessionObject);
}


/*/
 *  Check that the inputted password for the inputted username matches the one in the database
/*/
const authenticateKnownUser = (response, sessionInfo, userObject, password) => {

    const dbUsername = userObject.username;
    const dbPassword = userObject.password;

    // Hash check the inputted password against the one in the database.
    bcrypt.compare(password, dbPassword, (err_hash, successful_login) => {

        if (err_hash) throw err_hash;

        if (successful_login) {
            sessionInfo.user = dbUsername;
            sessionInfo.loggedin = true;
            // Should successfully logging in reset the incorrect login attempts?
            // resetLockOut(dbUsername);
        } else {
            sessionInfo.incorrectLoginAttempts++;
            if (sessionInfo.incorrectLoginAttempts === 3) {
                sessionInfo.lockedOut = true;
            }
            punishBadLogin(userObject);
        }
        sendAuthenticationResults(response, sessionInfo, true);
    });
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
server.post('/authenticate', (request, response) => {

    let sessionInfo = request.session;

    const username = sanitize(request.body.username);
    const password = sanitize(request.body.password);

    const lockOutDurationSeconds = 86400
    const lockOutDuration = lockOutDurationSeconds * 1000;

    sessionInfo.user = (username ? username : "");
    sessionInfo.lockedOut = false;
    sessionInfo.loggedin = false;
    sessionInfo.unknownUsername = false;
    sessionInfo.incorrectLoginAttempts = 0;
    sessionInfo.id = request.sessionID;

    if (!username || !password) {
        response.sendStatus(400);
        logLoginSessionInfo(sessionInfo);
    } else {

        // find username in dbCollection in dbName and get the username,password object for that user
        client.db(dbName).collection(dbCollection).find({ 'username': username }).toArray(function (err_db, userObjectArray) {

            if (err_db) throw err_db;

            let userObject = userObjectArray[0];

            if (!userObject) { // Username does not exist
                sessionInfo.unknownUsername = true;
                sendAuthenticationResults(response, sessionInfo, true);
            } else {

                sessionInfo.incorrectLoginAttempts = userObject.incorrectLoginAttempts;

                const lockOutTime = userObject.lockOutTime;
                const lockOutTimePassed = Date.now() - lockOutTime;
                const lastIncorrectAttemptTime = userObject.lastIncorrectAttemptTime;
                const lastIncorrectAttemptTimePassed = Date.now() - lastIncorrectAttemptTime;

                if (lockOutTimePassed >= lockOutDuration) {  // The user is not locked out
                    if (lockOutTime > 0 || (lastIncorrectAttemptTimePassed >= lockOutDuration && lastIncorrectAttemptTime > 0)) {  // The user's lockOut has expired
                        resetLockOut(username);
                    }
                    authenticateKnownUser(response, sessionInfo, userObject, password);
                } else {  // The user is locked out.
                    console.log(
                        "----------------------------------------------------------------------\n" +
                        "User " + username + ", tried to login, but they are locked out. ⛔\n" +
                        "----------------------------------------------------------------------\n"
                    );
                    sessionInfo.lockedOut = true;
                    sendAuthenticationResults(response, sessionInfo, true);
                }
            }
        });
    }
});


/*/
 *  Get the login status for a session
 *
 *  Response Format:
 *  {
 *        "loginStatus" : boolean  -- True if the user is logged in, else false.
 *        "expires"     : Date     -- The Date/Time of when the session cookie will expire. 
 *  }
/*/
server.get('/authenticate', (request, response) => {
    if (request.session.loggedin) {
        console.log(
            "----------------------------------------------------------------------\n" +
            "Auto-Redirected: " + request.session.user + " ✅\n" +
            "----------------------------------------------------------------------\n"
        );
        response.send({ "expires": request.session.cookie.expires, "loginStatus": true });
    } else {
        response.send({ "expires": request.session.cookie.expires, "loginStatus": false });
    }
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
server.post('/create-account', (request, response) => {

    let sessionInfo = request.session;

    const email    = sanitize(request.body.email);
    const username = sanitize(request.body.username);
    const password = sanitize(request.body.password);

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
        bcrypt.genSalt(saltRounds, (err_salt, salt) => {

            if (err_salt) throw err_salt;

            bcrypt.hash(password, salt, (err_hash, hash) => {

                if (err_hash) throw err_hash;

                // Check if email already exists
                client.db(dbName).collection(dbCollection).find({ 'email': email }).toArray( (err_findEmail, result) => {

                    if (err_findEmail) throw err_findEmail;

                    if (result[0]) {
                        res['emailInUse'] = true;
                        response.send(res);
                    } else {

                        // Check if username already exists
                        client.db(dbName).collection(dbCollection).find({ 'username': username }).toArray( (err_findUser, result) => {

                            if (err_findUser) throw err_findUser;

                            if (result[0]) {
                                res['usernameInUse'] = true;
                                response.send(res);
                            } else {

                                const user = {
                                    "email": email,
                                    "username": username,
                                    "password": hash,
                                    "incorrectLoginAttempts": 0,
                                    "lastIncorrectAttemptTime": 0,
                                    "lockOutTime": 0
                                }

                                // Insert the new user into the database
                                client.db(dbName).collection(dbCollection).insertOne(user, (err_insert, result) => {

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
 * Force a logout by destroying the user's session cookie.
/*/
server.post('/logout', (request, response) => {
    
    const id = request.sessionID;
    
    request.session.destroy();
    response.sendStatus(200);

    console.log(
        "----------------------------------------------------------------------\n" +
        "Session: " + id + " has timed-out and has been destroyed.\n" +
        "----------------------------------------------------------------------\n"
    );
});


/*/
 *  This is the user's home page: they should only get
 *  here if they are logged in.
/*/
server.get('/home', (request, response) => {
    if (request.session.loggedin) {
        response.send(
            '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>' +
            '<script src="/auth_guard.js"></script>' + 
            '<h1>Hey there ' + request.session.user + ', you are now logged in. ✅</h1>'
        );
    } else {
        response.redirect('http://localhost:8080/');
    }
});


server.listen(8080);
