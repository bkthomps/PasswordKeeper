<?php

$resource = "default";

/*****************************************************************************
 * This file contains APIs that you must use to implement server resources.
 * There are two classes, Request and Response, and a function log_to_console.
 *****************************************************************************/

/**
 * This is a global function that can be used to log to the console.
 * Students MUST use this for operational and error logging.
 */
function log_to_console($message) {
  error_log($GLOBALS["resource"] . ": " . $message);
}

/**
 * Request - the request object that will be used to pass values from the client.
 * Request objects will be constructed by the arbitration code and passed by reference 
 * to the resource functions, so resources should not create new ones.
 * Students may want to use the following methods:
 *   param     - get the value of a parameter passed by the client
 *   token     - get the value of a token passed by the client, presumably having been set by a Response
 *   cookie    - get the value of a cookie passed by the client, presumably having been set by a Response
 *   client_ip - get the IP address of the client if it is known
 *   header    - get the value of a request header from the client
 */ 
class Request {
  private $params;
  private $tokens;
  private $cookies;
  private $client_ip;
  private $headers;

  function __construct($json_body) {
    $this->params = $json_body;

    // get any passed tokens
    $this->tokens = array();
    if (isset($json_body["tokens"])) {
      $this->tokens = $json_body["tokens"];
    }
    // try to get a client IP
    $this->client_ip = "";
    if (isset($_SERVER["REMOTE_ADDR"])) {
      $this->client_ip = $_SERVER["REMOTE_ADDR"];
    }
    
    $this->cookies = $_COOKIE;
    $this->headers = getallheaders();
  }
  
  /**
   * Gets a parameter having been passed by the client.
   * An example of this use of params is the following.
   * 1. The client sends a serverRequest to the "foo" resource:
   *     serverRequest("foo", {"bar":123, "baz":"deadbeef"});
   * 2. The server.php arbitrates this request to the "foo" function in resources.php.
   *    (note that it will not actually do this, it only arbitrates valid resources)
   * 3. The foo function retrieves the bar and baz params:
   *     function foo (&$request, &$response, &$db) {
   *       $bar = $request->param("bar"); // $bar = 123
   *       $baz = $request->param("baz"); // $baz = "deadbeef"
   *       ...
   *     }
   * Returns false if no such parameter was set.
   */
  function param($key) {
    if (isset($this->params[$key])) {
      return $this->params[$key];
    }
    return false;
  }
  
  /**
   * Gets a token returned by the client.
   * This is the counterpart of the Response::set_token method.
   * Tokens work just like cookies from the perspective of the server, in that they
   * should always be returned in subsequent requests after they have been set in 
   * a response.  The client handling of this is done in client.js and students 
   * do not need to do anything to make the mechanism work.
   * The difference between tokens and cookies is that tokens are passed in the 
   * data, not the headers, of requests and responses.  Because of this, tokens are 
   * available to JavaScript, while the cookies set by Response::set_cookies are not.
   * Returns false if no such token was set.
   */
  function token($name) {
    if (isset($this->tokens[$name])) {
      return $this->tokens[$name];
    }
    return false;
  }
  
  /**
   * Gets a cookie returned by the client.
   * This is the counterpart of the Response::set_cookie method.
   * Cookies are sent by the client in the request headers.  After being set by
   * the set_cookie method they should always be returned by subsequent requests, 
   * unless they expire.  Unlike tokens, cookies can expire and can also be 
   * deleted.  The Response object also sets cookies to HTTP-only, meaning they
   * cannot be read by JavaScript.
   * Returns false if no such cookie was set.
   */
  function cookie($name) {
    if (isset($this->cookies[$name])) {
      return $this->cookies[$name];
    }
    return false;
  }
  
  /**
   * Gets the client IP address if it is available.
   * This gets the client IP address.  It may not be available in all cases.
   * If the IP address is not available will return empty string.
   */
  function client_ip() {
    return $this->client_ip;
  }
  
  /**
   * Gets a header from the client request.
   * This method gets the raw data from the client headers.  It should be used
   * sparingly, as most of the information the server needs from a request can be
   * obtained via the other Request methods.  However, the method is available if
   * you want direct access to the headers.
   * Returns false if no such header was set.
   */   
  function header($name) {
    if (isset($this->headers[$name])) {
      return $this->headers[$name];
    }
    return false;
  }
}

/**
 * Response - the response object that will be used to pass values to the client.
 * Reponse objects will be constructed by the arbitration code and passed by reference 
 * to the resource functions, so resources should not create new ones.
 * Students may want to use the following methods:
 *   set_http_code - sets the HTTP response code
 *   success       - signals the operation succeeded and sends a success message
 *   failure       - signals the operation failed and sends a failure message
 *   add_cookie    - adds a cookie to be stored by the client and returned with future requests
 *   delete_cookie - tells the client to delete a cookie
 *   set_token     - adds a token to be stored by the client and returned with future requests
 *   set_data      - sets arbitrary data items to be returned to the client
 */ 
class Response {
  private $resource;
  private $response_code;
  private $message;
  private $succeeded;
  private $cookies;
  private $tokens;
  private $data;

  function __construct($resource) {
    $GLOBALS["resource"] = $resource;
    $this->resource = $resource;
    $this->succeeded = false;
    $this->response_code = 500;
    $this->message = "Internal Server Error";
    $this->cookies = array();
    $this->tokens = array();
    $this->data = array();
  }
  
  /**
   * Sets an HTTP response code.
   * The code should be an integer.
   * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Status for valid codes.
   */
  function set_http_code($code) {
    $this->response_code = $code;
  }
  
  /**
   * Marks the response as one of success and sets a success message.
   * Note that this method does not set an HTTP response code!
   */
  function success($message) {
    $this->succeeded = true;
    $this->message = $message;
  }
  
  /**
   * Marks the response as one of failure and sets a failure message.
   * Note that this method does not set an HTTP response code!
   */
  function failure($message) {
    $this->succeeded = false;
    $this->message = $message;
  }
  
  /**
   * Sets a cookie that will be sent to the client.
   * Cookies should be returned by the client in each subsequent request until they expire
   * or they are deleted. Leaving the $expires parameter as the default value will set 
   * expiry to "session" meaning the cookie will be deleted once the user closes their
   * browser.  To set an explicit expiry use a Unix timestamp.
   * The options argument is an associative array keys that will be added to the call
   * to setcookie in server.php.  See https://www.php.net/manual/en/function.setcookie
   * for details on possible options and their values.
   */
  function add_cookie($name, $value, $expires = 0, $options = array()) {
    $this->cookies[] = ["name" => $name, 
                        "value" => $value, 
                        "expires" => $expires,
                        "options" => $options];
  }
  
  /**
   * Tells the client to remove a cookie that was previously set.
   * This is accomplished by setting an expiration date in the past.
   */
  function delete_cookie($name) {
    // set the expiration to the past to force deletion
    $this->add_cookie($name, "", time() - 86400);
  }

  /**
   * Set a token on the response, which the client should return in every subsequent request.
   * As mentioned above, tokens work just like cookies in that they are automatically 
   * stored and passed again by the client.  Tokens are also session length, meaning they will
   * be removed once the user closes the tab.  Unlike cookies, tokens have no expiry and may
   * not be deleted by the server (although you could override their value).  They are 
   * passed in the data returned to the client and not via response headers.
   */
  function set_token($name, $value) {
    $this->tokens[$name] = $value;
  }
  
  /**
   * Set arbitrary response data that the client code may use.
   * This is how resources should return data to the client.
   * An example of the use of set_data is the following.
   * 1. The client calls a resource "foo":
   *      serverRequest("foo", {}).then(myHandler);
   * 2. The request is arbitrated to the resources.php function foo.
   * 3. The foo function sets some data:
   *      function foo (&$request, &$response, &$db) {
   *        $response->set_data("gabba", "goo");
   *        ...
   *      }
   * 4. The client gets the data from the resulting json (JS):
   *      function myHandler(result) {
   *        var gabba = result.json.gabba; // gabba = "goo"
   *        ...
   *      }
   */
  function set_data($name, $value) {
    $this->data[$name] = $value;
  }
  
  /***************************************************
   * Code below here should not be needed by students.
   * It is all just used by server.php.
   ***************************************************/

  /**
   * Gets the last code that was set.
   * Generally students should not need to use this.  It is used by server.php to construct the
   * response.
   */
  function get_http_code() {
    return $this->response_code;
  }
  
  /**
   * Get all the cookies that have been set on this Response object.
   * Students should not need to use this method, which is here for the benefit of server.php
   * so it can build the response.
   */
  function get_cookies() {
    return $this->cookies;
  }
  
  /**
   * Gets the JSON that should be returned to the client.
   * This function should not be used directly by students, but is used by server.php.
   */
  function json() {
    $response = $this->data;
    if ($this->succeeded) {
      $response["success"] = $this->message;
    } else {
      $response["failure"] = $this->message;
    }
    
    if (count($this->tokens) > 0) {
      $response["tokens"] = $this->tokens;
    }
    
    return json_encode($response);
  }
  
}

?>