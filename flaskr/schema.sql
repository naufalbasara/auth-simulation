DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS user_biometric CASCADE;
DROP TABLE IF EXISTS user_codeword CASCADE;
DROP TABLE IF EXISTS user_sof CASCADE;
DROP TABLE IF EXISTS issuers CASCADE;
DROP TABLE IF EXISTS merchants CASCADE;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  nik VARCHAR NOT NULL,
  full_name VARCHAR NOT NULL,
  BID_identifier VARCHAR UNIQUE NOT NULL,
  registered_at TIMESTAMP
);

CREATE TABLE user_biometric (
  id SERIAL primary key,
  user_id integer references users(id),
  embedding vector(512),
  created_at TIMESTAMP,
  last_updated TIMESTAMP
);

CREATE TABLE user_codeword (
  id SERIAL primary key,
  user_id integer references users(id),
  helper_data VARCHAR,
  codeword VARCHAR,
  ecc VARCHAR,
  created_at TIMESTAMP,
  last_updated TIMESTAMP
);

CREATE TABLE issuers (
  id SERIAL primary key,
  issuer_code VARCHAR,
  name VARCHAR,
  registered_by VARCHAR,
  registered_at TIMESTAMP
);

CREATE TABLE user_sof (
  id SERIAL primary key,
  user_id integer references users(id),
  account_number VARCHAR,
  issuer_id integer references issuers(id),
  default_sof boolean,
  registered_at TIMESTAMP
);