var express = require('express');
var session = require('express-session');
var path = require('path');

var app = express();

app.use(session({
	secret: '123456',
	resave: true,
	saveUninitialized: true
}));
app.use(express.urlencoded({extended : true}));
app.use(express.json());

app.get('/', function(request, response) {
	response.sendFile(path.join(__dirname + '/login.html'));
});

app.post('/authenticate', function(request, response) {
	var username = request.body.username;
	var password = request.body.password;
	if (username && password) {
		request.session.loggedin = true;
		request.session.username = username;
		response.redirect('/home')
	}
});

app.get('/home', function(request, response) {
	if(request.session.loggedin) {
		console.log("User " + request.session.username + " has logged in.")
		response.sendFile(path.join(__dirname + '/home.html'));
	} else {
		response.send('You are not logged in.');
	}
});

app.listen(8080);