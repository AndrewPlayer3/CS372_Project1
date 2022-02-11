/*/ 
 * Script for Session Authentication Checking and Timeout Monitoring
/*/

const inactivityTimeoutSeconds = 15;

let expiresAt = 0;
let expired = false;
let lastActive = Date.now();

// Get whether the session is logged in, and when it expires.
$.ajax({
    url: 'http://localhost:8080/authenticate',
    method: 'get',
    data: {}
}).done( (data) => {
    if (
        data.loginStatus === true &&
        window.location.href != 'http://localhost:8080/home'
    )  {

        window.location.href = "/home";
    }
    expiresAt = data.expires;
});


// If the session is expired, alert the user and force redirect to the login page.
setInterval( () => {
    
    if (expired) return;

    let expiresIn = Date.parse(expiresAt) - Date.now();
    let inactiveTime = Date.now() - lastActive;
    
    if (inactiveTime > inactivityTimeoutSeconds * 1000) {
        timeoutSession();
    } else if (expiresIn < 0) {
        expired = true;
        alert('💤 This session has expired. 💤\nPlease login again. ')
        window.location.href = "/";
    }

}, 1000);


// Destroy the session, alert the user, and redirect to the login page if they have been inactive too long.
const timeoutSession = () => {
    if (expired) return;
    $.ajax({
        url: 'http://localhost:8080/logout',
        method: 'post',
        data: {}
    }).done(function(data) {
        expired = true;
        alert('💤 This session has expired. 💤\nPlease login again. ');
        window.location.href = "/";
    });
}


const touchActivity = () => {
    lastActive = Date.now(); 
}


const userActivityTrackers = () => {
  window.addEventListener("mousemove", touchActivity);
  window.addEventListener("scroll", touchActivity);
  window.addEventListener("keydown", touchActivity);
  window.addEventListener("resize", touchActivity);
}


userActivityTrackers();
