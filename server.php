<?php
/**
 * This file contains the request arbitration code for the password safe server.
 * Students are not allowed to modify this file.
 **/

// include the APIs that students should use
require("api.php");
 
// Define constants for use when function calls require flags
define("CREATE_ASSOC_ARRAYS", true);
define("STRICT_TYPES", true);
define("COOKIE_PATH", "");
define("COOKIE_DOMAIN", "");
define("NOT_SECURE", false);

// The request method
$request_method = $_SERVER["REQUEST_METHOD"];
// This is one way to get the raw post body in PHP
$decoded_post_body = json_decode(file_get_contents('php://input'), CREATE_ASSOC_ARRAYS);
// Just get the names of GET params, not the values
$url_params = array_keys($_GET);
// Get a PDO database connection that  will throw exceptions on failures
$db = new PDO("sqlite:passwordsafe.db", NULL, NULL, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));

$request = new Request($decoded_post_body);
$response = null;

// Remove PHP globals - students must use the provided APIs instead.
unset($_SERVER);
unset($_COOKIE);
unset($_GET);
unset($_POST);
unset($_SESSION);

// include the resources code that students should modify
require("student.php");

// Arbitrate connections to different handler functions
// We only use POST -- this is mostly due to how PHP works
if ($request_method == "POST") {
  if (in_array("preflight", $url_params, STRICT_TYPES)) {
    $response = new Response("preflight");
    preflight($request, $response, $db);
  }
  else if (in_array("signup", $url_params, STRICT_TYPES)) {
    $response = new Response("signup");
    if (preflight($request, $response, $db)) {
      signup($request, $response, $db);
    }
  } 
  else if (in_array("identify", $url_params, STRICT_TYPES)) {
    $response = new Response("identify");
    if (preflight($request, $response, $db)) {
      identify($request, $response, $db);
    }
  }
  else if (in_array("login", $url_params, STRICT_TYPES)) {
    $response = new Response("login");
    if (preflight($request, $response, $db)) {
      login($request, $response, $db);
    }
  }
  else if (in_array("sites", $url_params, STRICT_TYPES)) {
    $response = new Response("sites");
    if (preflight($request, $response, $db)) {
      sites($request, $response, $db);
    }
  }
  else if (in_array("save", $url_params, STRICT_TYPES)) {
    $response = new Response("save");
    if (preflight($request, $response, $db)) {
      save($request, $response, $db);
    }
  }
  else if (in_array("load", $url_params, STRICT_TYPES)) {
    $response = new Response("load");
    if (preflight($request, $response, $db)) {
      load($request, $response, $db);
    }
  }
  else if (in_array("logout", $url_params, STRICT_TYPES)) {
    $response = new Response("logout");
    if (preflight($request, $response, $db)) {
      logout($request, $response, $db);
    }
  } 
  else {
    $response = new Response("default");
    $response->set_http_code(404); // Not found
    $response->failure("Resource not found");
  }
  
}

// This is an easy way to test functionality
// To run the code in this block, just make a request to localhost:8000/server.php?test
// Note that any code placed in this file will not be part of your submission.
if (in_array("test", $url_params)) {
  // echo phpinfo();
}

// Set response code
http_response_code($response->get_http_code());
// Set response headers
header("Content-Type: application/json");
header("Cache-Control: no-cache, must-revalidate");
// Set any cookies
foreach ($response->get_cookies() as $cookie) {
  // name, value, options
  // The default options are expires, path, domain, secure - others must be passed 
  // via Response::add_cookie
  setcookie($cookie["name"], $cookie["value"], 
    array_merge([ "expires"  => $cookie["expires"],
                  "path"     => COOKIE_PATH,
                  "domain"   => COOKIE_DOMAIN,
                  "secure"   => NOT_SECURE], // disable requiring https since it isn't supported
                $cookie["options"] // merge the options array from the cookie object
    )
  ); 
}
// Echo out the JSON encoded response body
echo $response->json();

?>