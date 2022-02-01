const bcrypt = require('bcrypt');
const {MongoClient} = require('mongodb');

/*/
 *  ❗ Database Information - Change this if yours is different doesn't match. ❗
/*/
const url = "mongodb://localhost:27017/";
const client = new MongoClient(url);
const dbName = "UserDB";
const dbCollection = "users";
client.connect();

/*/ 
 * User Format: 
 * ------------------------------
 * {
 *    "username" : "theUsername",
 *    "password" : "thePassword"
 * } 
 * ------------------------------
/*/

const username = "coolUsername";  // ❗ Change me! ❗
const password = "coolPassword";  // ❗ Change me! ❗

/*/
 * Hash the password and then add the user & hashed password to the
 * database, unless the username already exists.
/*/
const saltRounds = 10;
bcrypt.genSalt(saltRounds, function(err_salt, salt) {
    if (err_salt) throw err_salt;
    bcrypt.hash(password, salt, function(err_hash, hash) {
        if (err_hash) throw err_hash;
        client.db(dbName).collection(dbCollection).find({'username' : username}).toArray(function(err_find, result) {
            if (err_find) throw err_find;
            if (result[0]) {
                throw "User already exists! 😠";
            } else {
                const user = {
                    "username" : username,
                    "password" : hash
                }
                client.db(dbName).collection(dbCollection).insertOne(user, function(err_insert, result) {
                    if (err_insert) throw err_insert;
                    console.log("Added user " + username + ", with password " + hash + " to the database. 👍");
                });
            }
        });
    });
});