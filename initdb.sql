/**
 * This is the SQL schema for the password safe database.
 * You may not modify this script!
 * To run the script on the passwordsafe.db database, run
 *   sqlite3 passwordsafe.db < initdb.sql
 *
 * Most likely, you will not use all the fields in the schema.
 * The lack of documentation is intentional so as to not provide too many hints.
 * It is a bad idea to try to reverse engineer this schema to determine
 * your site design.  A better plan is to design the site and see how the
 * schema can accommodate your design.
 */

CREATE TABLE IF NOT EXISTS user (
  username varchar(255) PRIMARY KEY,
  passwd   varchar(255) NOT NULL,
  email    varchar(255) UNIQUE NOT NULL,
  fullname varchar(255),
  valid    boolean DEFAULT false,
  modified datetime
);

CREATE TABLE IF NOT EXISTS user_login (
  username  varchar(255) PRIMARY KEY,
  salt      varchar(255) NOT NULL,
  challenge varchar(255),
  expires   datetime,
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_session (
  sessionid  varchar(255) PRIMARY KEY,
  username   varchar(255) UNIQUE NOT NULL,
  expires    datetime NOT NULL,
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_session_sessionid_expires ON user_session(sessionid, expires);

CREATE TABLE IF NOT EXISTS web_session (
  sessionid  varchar(255) PRIMARY KEY,
  expires    datetime NOT NULL,
  metadata   varchar(255)
);
CREATE INDEX IF NOT EXISTS web_session_sessionid_expires ON web_session(sessionid, expires);

CREATE TABLE IF NOT EXISTS user_safe (
  siteid     integer PRIMARY KEY,
  username   varchar(255),
  site       varchar(255),
  siteuser   varchar(255),
  sitepasswd text NOT NULL,
  siteiv     varchar(255),
  modified   datetime,
  UNIQUE (username, site)
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);