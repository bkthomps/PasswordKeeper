"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the
 * password safe application.  The other file, client.js, must not be
 * modified.  That file handles page navigation, event handler binding, token
 * setting/retrieving, preflighting, and provides some utility functions that
 * this file should use for encoding/decoding strings and making server
 * requests.
 *
 * Do not use any method other than serverRequest to make requests to the
 * server!  It handles a few things including tokens that you must not
 * reimplement.
 *
 * Some of the functions in this file handle a form submission.  These
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.  It should populate the password form
 *                 element with the decrypted password.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - randomBytes -- Takes a number of bytes as an argument and returns
 *                    that number of bytes of crypto-safe random data
 *                    as a hexidecimal-encoded string.
 *   - hash -- Takes a string as input and hashes it using SHA-256.
 *             Returns a promise for the hashed value.
 *   - encrypt -- Takes a plaintext string, a key and an IV and encrypts
 *                the plaintext using AES-CBC with the key and IV.  The
 *                key must be a 32 byte hex-encoded string and the IV must
 *                be a 16 byte hex-encoded string.
 *                Returns a promise for the encrypted value, which is a
 *                hex-encoded string.
 *   - decrypt -- Takes a ciphertext hex-encoded string, a key and an IV and
 *                decrypts the ciphertext using AES-CBC with the key and IV.
 *                The key must be a 32 byte hex-encoded string and the IV
 *                must be a 16 byte hex-encoded string.
 *                Returns a promise for the decrypted value, which is a
 *                plaintext string.
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for promises!
 *      https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
 *
 * There are lots of resources online for how to use promises, so go learn
 * about them before starting on the project. It is crucial that students
 * understand how promises work, since they are used throughout the boilerplate.
 *
 *****************************************************************************/

let masterPassword;

/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */
async function credentials(username, password) {
  const payload = {"username": username};
  const idResult = await serverRequest("identify", payload);
  if (!idResult.response.ok) {
    serverStatus(idResult);
    return 0;
  }
  return idResult.json;
}

/**
 * Called when the user submits the log-in form.
 */
function login(userInput, passInput) {
  const username = userInput.value;
  const password = passInput.value;
  masterPassword = password;
  credentials(username, password).then(function (idJson) {
    if (idJson !== 0) {
      const payload = {
        "username": username,
        "password": password,
        "websessionid": idJson.websessionid,
        "challenge": idJson.challenge
      };
      serverRequest("login", payload).then(function (result) {
        if (result.response.ok) {
          const userDisplay = document.getElementById("userdisplay");
          userDisplay.innerHTML = result.json.fullname;
          showContent("dashboard");
        } else {
          serverStatus(result);
        }
      });
    }
  });
}

/**
 * Called when the user submits the signup form.
 */
function signup(userInput, passInput, passInput2, emailInput, fullNameInput) {
  const username = userInput.value;
  const password = passInput.value;
  const passwordConfirm = passInput2.value;
  const email = emailInput.value;
  const fullName = fullNameInput.value;
  if (password !== passwordConfirm) {
    status("Password does not match confirmation password");
    return;
  }
  if (password.length < 8) {
    status("Password must be at least 8 characters long");
    return;
  }
  if (password === username || password === email || password === fullName) {
    status("Password must not be the same as username, email, or full name");
    return;
  }
  if (username.length > 200 || password.length > 200 || email.length > 200 || fullName.length > 200) {
    status("Limit field length to 200 characters");
    return;
  }
  const payload = {"username": username, "password": password, "email": email, "fullname": fullName};
  serverRequest("signup", payload).then(function (result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}

/**
 * Called when the add password form is submitted.
 */
async function save(siteIdInput, siteInput, userInput, passInput) {
  // TODO: verify
  const siteId = siteIdInput.value;
  const site = siteInput.value;
  const siteUser = userInput.value;
  const sitePassword = passInput.value;
  const hashedPassword = await hash(masterPassword)
  const siteIv = randomBytes(16);
  const encrypted = await encrypt(sitePassword, hashedPassword, siteIv);
  const payload = {
    "siteid": siteId,
    "site": site,
    "siteuser": siteUser,
    "sitepasswd": encrypted,
    "hashedPassword": hashedPassword,
    "iv": siteIv
  };
  serverRequest("save", payload).then(function (result) {
    if (result.response.ok) {
      sites("save");
    }
    serverStatus(result);
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteid is a string (the site to load) and not
 * a form element.
 */
function loadSite(siteid, siteIdElement, siteElement, userElement, passElement) {
  // TODO: verify
  const payload = {"siteid": siteid};
  serverRequest("load", payload).then(async function (result) {
    if (result.response.ok) {
      siteElement.value = result.json.site;
      userElement.value = result.json.siteuser;
      const cypherText = result.json.sitepasswd;
      const hashedPassword = await hash(masterPassword);
      const siteIv = result.json.siteiv;
      passElement.value = await decrypt(cypherText, hashedPassword, siteIv);
    } else {
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // TODO: verify
  serverRequest("logout", {}).then(function (result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}
