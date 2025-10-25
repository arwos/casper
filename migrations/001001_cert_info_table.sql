-- SEQUENCE
CREATE SEQUENCE IF NOT EXISTS "cert_info__id__seq" INCREMENT 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1;

-- TABLE
CREATE TABLE IF NOT EXISTS "cert_info"
(
	"id" BIGINT DEFAULT nextval('cert_info__id__seq') NOT NULL,
	CONSTRAINT "cert_info__id__pk" PRIMARY KEY ( "id" ),
	"owner" BIGINT NOT NULL,
	CONSTRAINT "cert_info__owner__fk" FOREIGN KEY ( "owner" ) REFERENCES "auth" ( "id" ) ON DELETE CASCADE NOT DEFERRABLE,
	"subject" TEXT NOT NULL,
	"fingerprint" TEXT NOT NULL,
	"issuer_key_hash" TEXT NOT NULL,
	"issuer_name_hash" TEXT NOT NULL,
	"revoked" BOOLEAN NOT NULL,
	"revoked_reason" BIGINT NOT NULL,
	"created_at" TIMESTAMPTZ NOT NULL,
	"valid_until" TIMESTAMPTZ NOT NULL,
	"updated_at" TIMESTAMPTZ NOT NULL
);

-- INDEX
CREATE INDEX "cert_info__issuer_key_hash__idx" ON "cert_info" USING btree ( "issuer_key_hash" );

