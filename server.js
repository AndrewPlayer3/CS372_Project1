const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const html = require('html');
const path = require('path');
/*/ 
 *  ⛔ If you get a TextEncoder not Defined Error, you need to copy this
 *  ⛔ in the beginning of the file that gives the error:
 *  ⛔ const {TextEncoder, TextDecoder} = require('util');
/*/
const {MongoClient} = require('mongodb');
const { render } = require('express/lib/response');

/*/
 *  Database Information - Change this if yours is different doesn't match.
/*/
const url = "mongodb://localhost:27017/";
const client = new MongoClient(url);
const dbName = "UserDB";
const dbCollection = "users";
client.connect();


// We are using express as the web server.
var server = express();


/*/
 *  The user's session (cookie).
/*/
server.use(session({
	secret: '123456',
	resave: true,
	saveUninitialized: true,
}));
server.use(express.urlencoded({extended : true}));
server.use(express.json());


/*/
 *  Load the initial login page that has the form.
/*/
server.get('/', function(request, response) {
	response.sendFile(path.join(__dirname + '/login.html'));
});


/*/
 *  This accepts the post from the login for, and preforms the
 *  password check against the result from the mongodb.
 *  
 *  Responds:
 *  ---------
 *  {
 * 		"loginStatus" : boolean,		-- whether the user is logged in or not
 * 	    "incorrectAttempts" : integer,  -- how many times they failed logging in
 * 		"lockedOut" : boolean           -- whether the user's session is locked or not
 *  }
/*/
server.post('/authenticate', function(request, response) {
	
	if(request.session.infoSet == null) {
		request.session.infoSet = true;
		request.session.incorrectLoginAttempts = 0;
		request.session.loggedin = false;
		request.session.lockedOut = false;
	}

	var username = request.body.username;
	var password = request.body.password;

	console.log("Recieved request for user: " + username);

	if (username && password && !request.session.lockedOut) {
		client.db(dbName).collection(dbCollection).find({'username' : username}).toArray(function(err, result) {

			if (err) throw err;

			// result: [{"username" : "...", "password" : "..."}] //
			bcrypt.compare(password, result[0]['password'], function(err, result) {
				if (err) throw err;
				if(result) {
					request.session.user = username;
					request.session.loggedin = true;
					request.session.incorrectLoginAttempts = 0;
				} else {
					request.session.incorrectLoginAttempts = request.session.incorrectLoginAttempts + 1;
					if(request.session.incorrectLoginAttempts == 3) {
						request.session.lockedOut = true;
					}
				}
				console.log("Session Details: " + request.session.loggedin + " " + request.session.incorrectLoginAttempts);
				response.send({
					"loginStatus" : request.session.loggedin,
					"incorrectAttempts" : request.session.incorrectLoginAttempts,
					"lockedOut" : request.session.lockedOut
				});
				response.end();
			});
		});
	} else {
		response.send({
			"loginStatus" : request.session.loggedin,
			"incorrectAttempts" : request.session.incorrectLoginAttempts,
			"lockedOut" : request.session.lockedOut
		});
		response.end();
	}
});


/*/
 *  Post to find out if a user's session cookie is authenticated.
 *
 *  Responds:
 *  ---------
 *  {
 *  	"loginStatus" : boolen -- true if logged in, false if not.
 *  }
/*/
server.post('/sessionstatus', function(request, response) {
	if (request.session.loggedin) {
		console.log(request.session.user + " has been auto-redirected.");
		response.send({"loginStatus" : true});
	} else {
		response.send({"loginStatus" : false});
	}
	response.end();
});


/*/
 *  This is the user's home page: they should only get
 *  here if they are logged in.
/*/
server.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('<h1>Hey there ' + request.session.user + ', you are now logged in. ✅</h1>');
	} else {
		response.send(403, '<h1>Please login to view this page! ⛔</h1>');
	}
	response.end();
});


server.listen(8080);