const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const {MongoClient} = require('mongodb');

var server = express();


server.use(session({
	/*
	*  The user's session (cookie).
	*/
	secret: '123456',
	resave: true,
	saveUninitialized: true
}));
server.use(express.urlencoded({extended : true}));
server.use(express.json());


server.get('/', function(request, response) {
	/*
	*  Load the initial login page that has the form.
	*/
	response.sendFile(path.join(__dirname + '/login.html'));
});


server.post('/authenticate', function(request, response) {
	/*
	*  This accepts the post from the login for, and preforms the
	*  password check against the result from the mongodb. If it 
	*  is correct, the user gets redirected to /home, else they are
	*  told the username or password is incorrect.
	*/
	var username = request.body.username;
	var password = request.body.password;
	if (username && password) {
		const url = "mongodb://localhost:27017/";
		const client = new MongoClient(url);
		client.connect();
		client.db('UserDB').collection('users').find({'username' : username}).toArray(function(err, result) {
			// User Format: {"username" : "user", "password" : "pwd"} 
			if (err) throw err;
			bcrypt.compare(password, result[0]['password'], function(err, result) {
				if (err) throw err;
				if(result) {
					request.session.loggedin = true;
					response.redirect('/home');
				} else {
					response.send('Incorrect Username or Password');
				}
			});
		});
	} else {
		// User's should never get here from the login page.
		response.send('Please enter Username and Password!');
		response.end();
	}
});


server.get('/home', function(request, response) {
	/*
	*  This is the user's home page: they should only get
	*  here if they are logged in.
	*/
	if (request.session.loggedin) {
		response.send('You have logged in...');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

server.listen(8080);