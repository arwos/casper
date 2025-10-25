-- SEQUENCE
CREATE SEQUENCE IF NOT EXISTS "auth__id__seq" INCREMENT 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1;

-- TABLE
CREATE TABLE IF NOT EXISTS "auth"
(
	"id" BIGINT DEFAULT nextval('auth__id__seq') NOT NULL,
	CONSTRAINT "auth__id__pk" PRIMARY KEY ( "id" ),
	"token_id" UUID NOT NULL,
	CONSTRAINT "auth__token_id__unq" UNIQUE ( "token_id" ),
	"token_key" VARCHAR( 128 ) NOT NULL,
	"domains" TEXT[] NOT NULL,
	"locked" BOOLEAN NOT NULL,
	"created_at" TIMESTAMPTZ NOT NULL,
	"updated_at" TIMESTAMPTZ NOT NULL
);

