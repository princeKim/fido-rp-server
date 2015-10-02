-- Simple schema for the relying party database
create schema if not exists RelyingParty;

-- Account table
create table if not exists Account (

	Id				CHAR(22) NOT NULL PRIMARY KEY,
	First_Name		VARCHAR(50) NOT NULL,
	Last_Name		VARCHAR(50) NOT NULL,
	Email			VARCHAR_IGNORECASE(255) NOT NULL UNIQUE,
	IdXId			CHAR(26),
	Iterations		int NOT NULL,
	Salt			blob NOT NULL,
	Hashed_Password	blob NOT NULL,
	Last_Logged_In	Timestamp NOT NULL,
	CreatedDTM		Timestamp NOT NULL
);

CREATE UNIQUE INDEX  IF NOT EXISTS EMAIL_UNIQUE ON Account(Email);

CREATE INDEX  IF NOT EXISTS IDXID_INDEX ON Account(IdXId);

-- Audit table
create table if not exists Audit (
	Id				CHAR(22) NOT NULL PRIMARY KEY,
	Operation		VARCHAR(50) NOT NULL,
	Session_Id		CHAR(22) NULL,
	Account_Id		CHAR(22) NULL,
	Duration		BIGINT NOT NULL,
	CreatedDTM		Timestamp NOT NULL
);

-- Session table
create table if not exists Session (
	Id				CHAR(22) NOT NULL PRIMARY KEY,
	Account_Id		CHAR(22) NOT NULL,
	CreatedDTM		Timestamp NOT NULL,
	ExpiringDTM		Timestamp NOT NULL
);



	