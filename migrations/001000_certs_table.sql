-- SEQUENCE
CREATE SEQUENCE IF NOT EXISTS "certs__id__seq" INCREMENT 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1;

-- TABLE
CREATE TABLE IF NOT EXISTS "certs"
(
	"id" BIGINT DEFAULT nextval('certs__id__seq') NOT NULL,
	CONSTRAINT "certs__id__pk" PRIMARY KEY ( "id" ),
	"domain" VARCHAR( 254 ) NOT NULL,
	"subject" TEXT NOT NULL,
	"fingerprint" TEXT NOT NULL,
	"issuer_key_hash" TEXT NOT NULL,
	"issuer_name_hash" TEXT NOT NULL,
	"revoked" BOOLEAN NOT NULL,
	"created_at" TIMESTAMPTZ NOT NULL,
	"valid_until" TIMESTAMPTZ NOT NULL,
	"updated_at" TIMESTAMPTZ NOT NULL
);

-- INDEX
CREATE INDEX "certs__domain__idx" ON "certs" USING btree ( "domain" );
CREATE INDEX "certs__issuer_key_hash__idx" ON "certs" USING btree ( "issuer_key_hash" );

