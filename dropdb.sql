/**
 * This SQL script can be run to delete the schema and all corresponding data
 * from the password safe database.  It is handy if you want to start fresh.
 * To run the script:
 *   sqlite3 passwordsafe.db < dropdb.sql
 * Then, to recreate the database:
 *   sqlite3 passwordsafe.db < initdb.sql
 */

DROP INDEX web_session_sessionid_expires;
DROP TABLE web_session;
DROP TABLE user_safe;
DROP INDEX user_session_sessionid_expires;
DROP TABLE user_session;
DROP TABLE user_login;
DROP TABLE user;
