<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify
 * to implement the password safe application.  Another PHP file, server.php,
 * must not be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which also must not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 *
 * Student code in this file must only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both
 *                   as a separate "preflight" resource and it is also called
 *                   before every other resource to perform any preflight
 *                   checks and insert any preflight response.  It is
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any
 *                  information that the client would need to log in.  You
 *                  should be especially careful not to leak any information
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP
 * will set if there is an error executing the script) then we will assume
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database "passwordsafe.db".
 * The commands to create this database (and therefore its schema) can
 * be found in "initdb.sql".  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval("PT15M");
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using ===
 * (as in, if($result !== false ) {...}) because not using === or !== may
 * result in unexpected ceorcion of a valid response (0) to false.
 *
 *****************************************************************************/

function exists(&$object)
{
  return $object != false && !is_null($object) && $object !== "null";
}

/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db)
{
  if (!exists($request->header("Origin"))) {
    $response->set_http_code(403);
    $response->failure("Origin not provided");
    return false;
  }
  if (exists($request->token("web_session"))) {
    return preflight_valid_web_session($request, $response, $db);
  }
  return preflight_invalid_web_session($request, $response, $db);
}

function preflight_valid_web_session(&$request, &$response, &$db)
{
  try {
    $webSession = $request->token("web_session");
    // Get current web session expiry date
    $now = date("c");
    $sqlWebSessionId = "SELECT expires FROM web_session WHERE sessionid = '$webSession'";
    $webResult = $db->query($sqlWebSessionId);
    $webRow = $webResult->fetch(PDO::FETCH_ASSOC);
    // If the web session is expired, the user must login again
    if ($now > $webRow["expires"]) {
      $response->set_token("web_session", null);
      $response->delete_cookie("user_session");
      $response->set_http_code(401);
      $response->failure("Session expired, please login again");
      return false;
    }
    // Update the ip in the web session
    $client_ip = $request->client_ip();
    $sqlUpdateMetadata = "UPDATE web_session SET metadata = '$client_ip' WHERE sessionid = '$webSession'";
    $db->exec($sqlUpdateMetadata);
    // Check the user session expiry, unless it's a login or signup
    $operation = $request->param("operation");
    if ($operation !== "identify" && $operation !== "signup" && $operation !== "login") {
      $userSession = $request->cookie("user_session");
      // This happens if user clears their cookies
      if (!exists($userSession)) {
        $response->delete_cookie("user_session");
        $response->set_http_code(401);
        $response->failure("Session expired, please login again");
        return false;
      }
      $now = date("c");
      $sqlUserSession = "SELECT expires, COUNT(expires) AS count FROM user_session WHERE sessionid = '$userSession'";
      $userResult = $db->query($sqlUserSession);
      $userRow = $userResult->fetch(PDO::FETCH_ASSOC);
      // This should never happen
      if ($userRow["count"] == 0) {
        $response->set_http_code(500);
        $response->failure("Internal error");
        return false;
      }
      // Check if user session is expired
      if ($now > $userRow["expires"]) {
        $response->set_token("web_session", null);
        $response->delete_cookie("user_session");
        $response->set_http_code(401);
        $response->failure("Session expired, please login again");
        return false;
      }
      $later = date("c", time() + 15 * 60);
      $sqlUpdateExpiry = "UPDATE user_session SET expires = '$later' WHERE sessionid = '$userSession'";
      $db->exec($sqlUpdateExpiry);
    }
    $response->set_http_code(200);
    $response->success("Request OK");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(500);
    $response->failure("Internal server error, please try the same action again");
    return false;
  }
}

function preflight_invalid_web_session(&$request, &$response, &$db)
{
  try {
    $operation = $request->param("operation");
    // If there is no web session set, and it's not a signup or login, it is unauthorized
    if (exists($operation) && $operation !== "identify" && $operation !== "signup" && $operation !== "login") {
      $response->set_token("web_session", null);
      $response->delete_cookie("user_session");
      $response->failure("Unauthorized");
      $response->set_http_code(401);
      return false;
    }
    // There is an extremely small chance that this throws an error due to the session id
    // already existing. In that case, the user would be notified to try connecting again.
    $webSession = base64_encode(random_bytes(176));
    $later = date("c", time() + 12 * 60 * 60);
    $ip = $request->client_ip();
    $insert = "INSERT INTO web_session VALUES ('$webSession', '$later', '$ip')";
    $db->exec($insert);
    $response->set_token("web_session", $webSession);
    $response->set_http_code(200);
    $response->success("Request OK");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(500);
    $response->failure("Internal server error, please try the same action again");
    return false;
  }
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db)
{
  try {
    $username = $request->param("username");
    $password = $request->param("password");
    $email = $request->param("email");
    $fullName = $request->param("fullname");
    $salt = $request->param("salt");
    $sqlUnique = "SELECT username, email, COUNT(*) AS count FROM user WHERE username = '$username' OR email = '$email'";
    $result = $db->query($sqlUnique);
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row["count"] != 0) {
      $response->set_http_code(400);
      $response->failure("Either username or email has already been used");
      return false;
    }
    $now = date("c");
    $challenge = base64_encode(random_bytes(64));
    $sqlUser = "INSERT INTO user VALUES ('$username', '$password', '$email', '$fullName', 'true', '$now')";
    $db->exec($sqlUser);
    $sqlLogin = "INSERT INTO user_login VALUES ('$username', '$salt', '$challenge', '$now')";
    $db->exec($sqlLogin);
    // There is an extremely small chance that this throws an error due to the session id
    // already existing. In that case, the user would be notified to try connecting again.
    $randomSession = base64_encode(random_bytes(128));
    $now = date("c");
    $sqlUser = "INSERT INTO user_session VALUES ('$randomSession', '$username', '$now')";
    $db->exec($sqlUser);
    $response->set_http_code(201);
    $response->success("Account created");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(500);
    $response->failure("Internal server error, please try the same action again");
    return false;
  }
}

/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db)
{
  try {
    $username = $request->param("username");
    $sqlCount = "SELECT username, salt, COUNT(*) as count FROM user_login WHERE username = '$username'";
    $result = $db->query($sqlCount);
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row["count"] == 0) {
      $response->set_http_code(400);
      $response->failure("Username or password incorrect");
      return false;
    }
    $salt = $row["salt"];
    $challenge = base64_encode(random_bytes(64));
    $later = date("c", time() + 30);
    $sqlLogin = "UPDATE user_login SET challenge = '$challenge', expires = '$later' WHERE username = '$username'";
    $db->exec($sqlLogin);
    $response->set_data("salt", $salt);
    $response->set_data("challenge", $challenge);
    $response->set_http_code(200);
    $response->success("Successfully identified user");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(500);
    $response->failure("Internal server error, please try the same action again");
    return false;
  }
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db)
{
  try {
    $username = $request->param("username");
    $password = $request->param("password");
    $challenge = $request->param("challenge");
    $now = date("c");
    $sqlUserLogin = "SELECT salt, challenge, expires FROM user_login WHERE username = '$username'";
    $loginResult = $db->query($sqlUserLogin);
    $loginRow = $loginResult->fetch(PDO::FETCH_ASSOC);
    if ($now > $loginRow["expires"] || $challenge !== $loginRow["challenge"]) {
      $response->set_token("web_session", null);
      $response->delete_cookie("user_session");
      $response->set_http_code(401);
      $response->failure("Invalid authentication");
      return false;
    }
    $challenge = base64_encode(random_bytes(64));
    $now = date("c");
    $sqlResetLogin = "UPDATE user_login SET challenge = '$challenge', expires = '$now' WHERE username = '$username'";
    $db->exec($sqlResetLogin);
    $sql = "SELECT fullname, COUNT(*) as count FROM user WHERE username = '$username' AND passwd = '$password'";
    $result = $db->query($sql);
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row['count'] == 0) {
      $response->set_http_code(401);
      $response->failure("Username or password incorrect");
      return false;
    }
    // This could technically be a duplicate, but the user should just try again once the
    // user receives the internal server error. This chance is extremely small, however.
    $userSession = base64_encode(random_bytes(128));
    $later = date("c", time() + 15 * 60);
    $sqlUpdateExpiry = "UPDATE user_session SET sessionid = '$userSession', expires = '$later' WHERE username = '$username'";
    $db->exec($sqlUpdateExpiry);
    $fullName = $row['fullname'];
    $response->add_cookie("user_session", $userSession, time() + 15 * 60);
    $response->set_http_code(200);
    $response->set_data("fullname", $fullName);
    $response->success("Successfully logged in");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(500);
    $response->failure("Internal server error, please try the same action again");
    return false;
  }
}

function get_user_name(&$request, &$response, &$db)
{
  $userSession = $request->cookie("user_session");
  $sqlSession = "SELECT username FROM user_session WHERE sessionid = '$userSession'";
  $resultSession = $db->query($sqlSession);
  $rowSession = $resultSession->fetch(PDO::FETCH_ASSOC);
  return $rowSession["username"];
}


/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db)
{
  $userName = get_user_name($request, $response, $db);
  $sql = "SELECT site, siteid FROM user_safe WHERE username = '$userName'";
  $result = $db->query($sql);
  $rows = $result->fetchall(PDO::FETCH_ASSOC);
  $all_sites = array();
  $all_siteids = array();
  foreach ($rows as $row) {
    $site = $row["site"];
    $siteid = $row["siteid"];
    array_push($all_sites, $site);
    array_push($all_siteids, $siteid);
  }
  $response->set_data("sites", $all_sites);
  $response->set_data("siteids", $all_siteids);
  $response->set_http_code(200);
  $response->success("Sites with recorded passwords");
  return true;
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db)
{
  $userName = get_user_name($request, $response, $db);
  $siteId = $request->param("siteid");
  $site = $request->param("site");
  $siteUser = $request->param("siteuser");
  $sitePassword = $request->param("sitepassword");
  $iv = $request->param("iv");
  $now = date("c");
  $exists = "SELECT site, COUNT(site) AS count FROM user_safe WHERE siteid = '$siteId'";
  $resultExists = $db->query($exists);
  $rowExists = $resultExists->fetch(PDO::FETCH_ASSOC);
  try {
    if ($rowExists["count"] == 0) {
      $sql = "INSERT INTO user_safe (username, site, siteuser, sitepasswd, siteiv, modified) "
        . "VALUES ('$userName', '$site', '$siteUser', '$sitePassword', '$iv', '$now')";
      $db->exec($sql);
      $response->set_http_code(200);
      $response->success("Successfully saved to safe");
      return true;
    }
    $sql = "UPDATE user_safe SET site = '$site', siteuser = '$siteUser', sitepasswd = '$sitePassword', "
      . "siteiv = '$iv', modified = '$now' WHERE siteid = '$siteId'";
    $db->exec($sql);
    $response->set_http_code(200);
    $response->success("Successfully updated to safe");
    return true;
  } catch (Exception $e) {
    $response->set_http_code(412);
    $response->failure("This site is already saved");
    return false;
  }
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db)
{
  $siteid = $request->param("siteid");
  $sql = "SELECT site, siteuser, sitepasswd, siteiv FROM user_safe WHERE siteid = '$siteid'";
  $result = $db->query($sql);
  $row = $result->fetch(PDO::FETCH_ASSOC);
  $site = $row["site"];
  $siteuser = $row["siteuser"];
  $sitepasswd = $row["sitepasswd"];
  $siteiv = $row["siteiv"];
  $response->set_data("site", $site);
  $response->set_data("siteuser", $siteuser);
  $response->set_data("sitepasswd", $sitepasswd);
  $response->set_data("siteiv", $siteiv);
  $response->set_http_code(200);
  $response->success("Site data retrieved.");
  return true;
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db)
{
  $userSession = $request->cookie("user_session");
  $now = date("c");
  $invalidate = "UPDATE user_session SET expires = '$now' WHERE sessionid = '$userSession'";
  $db->exec($invalidate);
  $response->delete_cookie("user_session");
  $response->set_http_code(200);
  $response->success("Successfully logged out");
  return true;
}

?>
