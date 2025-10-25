-- TABLE
CREATE TABLE IF NOT EXISTS "cert_domain"
(
	"cert_id" BIGINT NOT NULL,
	CONSTRAINT "cert_domain__cert_id__fk" FOREIGN KEY ( "cert_id" ) REFERENCES "cert_info" ( "id" ) ON DELETE CASCADE NOT DEFERRABLE,
	"domain" TEXT NOT NULL
);

-- INDEX
CREATE INDEX "cert_domain__domain__idx" ON "cert_domain" USING btree ( "domain" );

