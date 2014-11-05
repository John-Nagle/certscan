--
--  certscan.sql -- tables for SSL certificate analysis
--
--  Used by certscan program to analyze U. Mich. 
--  SSL certificate dumps.  Not of permanent value;
--  stored in SQL format to allow easy data analysis.
--
--
--  UTF-8 everywhere
--
USE sslcerts;
ALTER DATABASE sslcerts DEFAULT collate utf8_general_ci DEFAULT character set utf8;
--
--  certs - fields of interest from U. Mich. certificate dump
--
CREATE TABLE certs (
    --  Fields from U. Mich certificate dump
	Certificate_id                   BIGINT PRIMARY KEY,
	####Hex_encoded_SHA_1_fingerprint    string
	Serial_number                    BIGINT,
	Issuer_id                        BIGINT,
	Version                          TINYTEXT,
	####Subject                          string,
	####Issuer                           string
	Is_ca                            BOOL,
	Is_self_signed                   BOOL,
	Not_valid_before_time            DATETIME,
	Not_valid_after_time             DATETIME,
	Is_valid                         BOOL,
	OpenSSL_validation_error         TEXT,
	Is_ubuntu_valid                  BOOL,
	Is_mozilla_valid                 BOOL,
	Is_windows_valid                 BOOL,
	Is_apple_valid                   BOOL,
	####X_509_basicConstraints           string
	####X_509_crlDistributionPoints      string
	####X_509_extendedKeyUsageidentifier string
	####X_509_authorityKeyIdentifier     string
	####X_509_subjectKeyIdentifier       string
	####X_509_keyUsage                   string
	####X_509_certificatePolicies        string
	####X_509_authorityInfoAccess        string
	####X_509_subjectAltName             string
	####X_509_nsCertType                 string
	####X_509_nsComment                  string
	####X_509_policyConstraints          string
	####X_509_privateKeyUsagePeriod      string
	####X_509_SMIME_CAPS                 string
	####X_509_issuerAltName              string
	####Signature_algo                   string
	Depth                            SMALLINT,
	####Public_key_id                    string
	####First_seen_at                    string
	####Public_key_type                  string
	####In_ubuntu_root_store             string
	####In_mozilla_root_store            string
	####In_windows_root_store            string
	####In_apple_root_store              string
	Is_revoked                       BOOL,
	####Revoked_at                       string
	Reason_revoked                   TEXT,
    --  Derived fields extracted from certificate.
    Issuer_name                     VARCHAR(127),
    Subject_commonname              VARCHAR(127),
    Subject_organization            TEXT,
    Subject_organizationunit        TEXT,
    Subject_location                TEXT,
    Subject_countrycode             TEXT(2),
    Is_browser_valid                BOOL,  -- at least one major browser vendor accepts this cert
    Error_message                   TEXT
);

--
--  domains  -- Domains associated with certificates above.
--
--  Only unique second level domains are stored.
--  Subdomains are not stored here.
--
CREATE TABLE domains (
    Certificate_id                  BIGINT,
    Domain_2ld                      VARCHAR(127)   -- "2ld.tld", no subdomains
);
--
--  policies --  Certificate policy OIDs associated with certificates above
--
    CREATE TABLE policies (
        Certificate_id                  BIGINT,
        OID                             VARCHAR(20)
);
