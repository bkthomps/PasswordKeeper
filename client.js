"use strict";

/*******************************************************************
 * This file should not be modified by students!
 * It provides boilerplate for application functionality and some
 * utility functions.
 *******************************************************************/
var currentPage = "default";


/*******************************************************************
 * This top part of the file contains the utility functions that 
 * students will need to use in their code.
 *******************************************************************/


/**
 * Gets a specified number of bytes of crypto-safe random data.
 * Returns the random data as a hexidecimal-encoded string.
 * Students should use this function to get random bytes in JavaScript.
 * For example, to get 8 bytes of data:
 *   var r = randomBytes(8);
 */
function randomBytes(sizeInBytes) {
  // get a container for the bytes
  var bytes = new Uint8Array(sizeInBytes);

  // populate the container with cypto safe random values
  crypto.getRandomValues(bytes);
  
  // return the bytes as a string
  return bufferToHexString(bytes);
}

/**
 * Hashes the passed plaintext string using SHA-256.
 * The plaintext should be passed as a string.
 * Returns a promise for the hash as a hexidecimal-encoded string.
 * To call this function from an async function:
 *   var h = await hash(text);
 * To call this function from a non-async function:
 *   hash(text).then(function (h) {
 *     // h is the hash
 *   });
 */
async function hash(plaintext) {
  // convert the passed string to a typed array
  var plainTyped = utf8ToUint8Array(plaintext);

  // get the promise for the hash
  var hashed = await crypto.subtle.digest("SHA-256", plainTyped);
  
  // hex-encode it
  return bufferToHexString(hashed);
}

/**
 * Encrypts a plaintext string with AES-CBC using the passed key and IV.
 * The plaintext should be a string.
 * The key should be a hexidecimal-encoded string of 32 bytes.
 * The IV should be a hexidecimal-encoded string of 16 bytes.
 * Returns a promise for the ciphertext as a hexidecimal-encoded string.
 * To call this function from an async function:
 *   var cipher = await encrypt(plaintext, key, iv);
 * To call this function from a non-async function:
 *   encrypt(plaintext, key, iv).then(function (cipher) {
 *     // cipher is the ciphertext
 *   });
 */
async function encrypt(plaintext, key, iv) {
  if (!isHexString(key, 32)) {
    throw "encrypt: key must be 32 bytes of data in a hexidecimal-encoded string!";
  }
  if (!isHexString(iv, 16)) {
    throw "encrypt: iv must be 32 bytes of data in a hexidecimal-encoded string!";
  }
  
      // encode the plaintext as a typed array
  var plainTyped  = utf8ToUint8Array(plaintext),
      // decode the key as a typed array
      keyTyped    = hexStringToUint8Array(key),
      // decode the iv as a typed array
      ivTyped     = hexStringToUint8Array(iv);

  // import the key
  var keyObject = await crypto.subtle.importKey("raw", keyTyped, "AES-CBC", false, ["encrypt"]);
  // encrypt
  var encrypted = await crypto.subtle.encrypt({ "name": "AES-CBC", "iv": ivTyped.buffer}, keyObject, plainTyped);

  // return the ciphertext as a hex-encoded string
  return bufferToHexString(encrypted);
}

/**
 * Decrypts a ciphertext string with AES-CBC using the passed key and IV.
 * The ciphertext should be a hexidecimal-encoded string.
 * The key should be a hexidecimal-encoded string of 32 bytes.
 * The IV should be a hexidecimal-encoded string of 16 bytes.
 * Returns a promise for the plaintext as a string.
 * To call this function from an async function:
 *   var plain = await encrypt(ciphertext, key, iv);
 * To call this function from a non-async function:
 *   decrypt(ciphertext, key, iv).then(function (plain) {
 *     // plain is the plaintext
 *   });
 */
async function decrypt(ciphertext, key, iv) {
  if (!isHexString(key, 32)) {
    throw "decrypt: key must be 32 bytes of data in a hexidecimal-encoded string!";
  }
  if (!isHexString(iv, 16)) {
    throw "decrypt: iv must be 32 bytes of data in a hexidecimal-encoded string!";
  }

      // encode the ciphertext as a typed array
  var cipherTyped = hexStringToUint8Array(ciphertext),
      // decode the key as a typed array
      keyTyped    = hexStringToUint8Array(key),
      // decode the iv to a typed array
      ivTyped     = hexStringToUint8Array(iv);

  // import the key
  var keyObject = await crypto.subtle.importKey("raw", keyTyped, "AES-CBC", false, ["decrypt"]);
  // encrypt
  var decrypted = await crypto.subtle.decrypt({ "name": "AES-CBC", "iv": ivTyped.buffer}, keyObject, cipherTyped);

  return bufferToUtf8(decrypted);
}

/**
 * This makes a request to the server using the passed parameters.
 * This function returns a promise for the response and json objects.
 */
async function serverRequest(resource, data) {
  data["tokens"] = getTokens();
  var response = await fetch("server.php?" + resource, {
    method: "POST",
    cache: "no-cache",
    credentials: "same-origin",
    redirect: "error",
    headers: {
      "Content-Type": "application/json"
    },
    referrer: "no-referrer",
    body: JSON.stringify(data)
  })

  var json = await response.json();
  setTokens(json);

  // it has to be done this way because json() consumes the body
  return {"response": response, "json": json};
}

/**
 * This function hides all the content divs except for the specified one.
 */
function showContent(page) {
  // First hide all the content divs
  var contentDivs = document.querySelectorAll(".content");
  for (let i = 0; i < contentDivs.length; i++) {
    contentDivs[i].style.display = "none";
  }
  // Remove any status messages
  status("");
  // then show the signup content
  document.getElementById(page).style.display = "block";
  // update the current page
  currentPage = page;
  // update the url
  document.location.hash = "#" + page;
}

/**
 * This displays an error or status message on the page.
 */
function status(message) {
  var messageDialog = document.getElementById("message");
  if (message) {
    messageDialog.textContent = message;
    messageDialog.style.display = "block";
  } else {
    messageDialog.style.display = "none";
  }
}

/**
 * This handles standard server status messages.
 * Use the function by passing in the parameter passed from the 
 * promise from a serverRequest.
 */
function serverStatus(response) {
  if ("success" in response.json) {
    status(response.json["success"]);
  } else if ("failure" in response.json) {
    status(response.json["failure"]);
  }
}




/*******************************************************************
 * Everything below this comment is boilerplate that students should
 * not call directly.  It is used to handle things like navigation.
 *******************************************************************/

const loader = {
  "save" : sites,
  "load" : sites,
  "logout" : logout
};

/**
 * Sets up the page, provides wrappers for action.
 */
function init() {
  // navigation
  window.onhashchange = navigate;
  
  // set up the forms
  var contentDivs = document.querySelectorAll(".content");
  for (let i = 0; i < contentDivs.length; i++) {
    let content = contentDivs[i];
    // each content div has at most one form
    let form = content.querySelector("form");
    if (form) {
      // if there is a form, attach a handler
      form.addEventListener("submit", function (event) {
        // get all the input elements
        let inputs = form.querySelectorAll("input, output");
      
        // call the action function, passing the form as this
        // and the inputs as the parameters
        window[content.id].apply(form, inputs);
        
        // Prevent form submission
        event.preventDefault();
        event.stopPropagation();
      });
    }
  }
  
  // call navigate, if it returns true then preflight
  if (navigate()) {
    serverRequest("preflight", {});
  }
  
}


/**
 * Sets any tokens passed from the server.
 * Tokens are stored using sessionStorage which is origin specific and 
 * cleared whenever the tab is closed.
 */
function setTokens(json) {
  if ("tokens" in json) {
    let tokens = [];
    for (let key in json["tokens"]) {
      sessionStorage.setItem(key, json["tokens"][key]);
      tokens.push(key);
    }
    sessionStorage.setItem("tokens", tokens.join(","));
  }
}

/**
 * Gets any tokens passed from the server.
 * Tokens are stored using sessionStorage which is origin specific and 
 * cleared whenever the tab is closed.
 */
function getTokens() {
  var keyString = sessionStorage.getItem("tokens");
  var tokens = {};

  if (keyString) {
    let tokenKeys = keyString.split(",");
    for (let i = 0; i < tokenKeys.length; i++) {
      let key = tokenKeys[i];
      tokens[key] = sessionStorage.getItem(key);
    }
  }
  return tokens;
}


/**
 * This function is called after the index page finishes rendering.
 * It is also called when the URL anchor hash changes.
 * The return value is used on page initialization.
 * If no other requests are being made on load, then return true so 
 * a preflight request will be sent.  If a request is being made on
 * load, return false and preflight will be bypassed.
 */
function navigate() {
  // First check the url to see if we should show a specific page
  var page = window.location.hash.substring(1), inputs;
  if (page === currentPage) {
    return true;
  }

  // clear any inputs
  inputs = document.querySelectorAll("form");
  for (let i = 0; i < inputs.length; i++) {
    inputs[i].reset();
  }

  if (page.length > 0) {
    // navigate to the page
    showContent(page);
    // if there is a data loader function for the page, call it
    if (page in loader) {
      loader[page](page);
      return false;
    }

  } else {
    // For now, just show the login page if no page is specified
    showContent("login");
  }
  return true;
}

/**
 * Called when either the add password or load password page loads.
 * Loads the sites data for the dropdown.  Assumes an active session.
 */
function sites(page) {
  // get the select element
  var select = document.querySelector("#" + page + " select[name=sitelist]");
  // bind a change handler (multiple binds for the same function are NOPs)
  select.addEventListener("change", loadSiteWrapper);

  // call the server to get the sites
  serverRequest("sites", {}).then(function (result) {
    if (result.response.ok) {
      let sites   = result.json.sites,
          siteids = result.json.siteids;

      // delete all but the first option
      let options = select.querySelectorAll("option");
      for (let i = 1; i < options.length; i++) {
        select.removeChild(options[i]);
      }
      // populate the dropdown
      for (let i = 0; i < sites.length; i++) {
        let option = document.createElement("option");
        option.textContent = sites[i];
        option.value = siteids[i];
        select.appendChild(option);
      }
    } else {
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * This function calls the student code so students don't have to figure out how
 * to get the form elements.
 */
function loadSiteWrapper(event) {
  // get the selected option
  var selected = this.selectedOptions[0],
      site = selected.textContent,
      siteid = selected.value;
  
  // get the form in the same page as this Select element
  var node = this;
  while (node != null && !node.className.includes("content")) {
    node = node.parentNode;
  }
  // we got the content div, now get the form
  var form = node.querySelector("form"),
      siteIdElement = form.querySelector("input[name=siteid]"),
      siteElement   = form.querySelector("input[name=site], output[name=site]"),
      userElement   = form.querySelector("input[name=siteuser], output[name=siteuser]"),
      passElement   = form.querySelector("input[name=sitepasswd], output[name=sitepasswd]");
  
  // if add new was selected, clear the inputs
  if (selected.value == "default") {
    if (siteIdInput) {
      siteIdInput.value = "";
    }
    siteElement.value = "";
    userElement.value = "";
    passElement.value = "";
    return false;
  }
  
  // otherwise, call the student code mostly the same way form submit code is called
  loadSite.call(form, siteid, siteIdElement, siteElement, userElement, passElement);
}

/**
 * Test if a string is a hex string of a specified length.
 */
function isHexString(str, bytes) {
  return typeof(str) == "string" && str.length == (bytes * 2) && /^[0-9a-fA-F]*$/.test(str);
}

/**
 * Takes a typed array (like a Uint8Array) or an ArrayBuffer and 
 * returns a hex encoded string for its values.
 */
function bufferToHexString(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * Takes a hex encoded string and returns a Uint8Array with the
 * hex decoded into its values.
 */
function hexStringToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

/**
 * Takes a typed array (like a Uint8Array) or an ArrayBuffer and
 * returns a string with its values decoded as UTF-8 characters.
 */
function bufferToUtf8(buffer) {
  return new TextDecoder("utf-8").decode(buffer);
}

/**
 * Takes a UTF-8 string and returns a Uint8Array with the character
 * codes as its values.
 */
function utf8ToUint8Array(utf8String) {
  return new TextEncoder("utf-8").encode(utf8String);
}