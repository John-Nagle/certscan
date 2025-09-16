Archived September 2025. 
This worked with a project that is now defunct.

-----------------------------------------------

Certscan README


Utility programs for processing SSL/TLS dump files from U. Mich.

The security group at the University of Michigan periodically
examines every IPv4 address on the Internet to see if it
will return an SSL/TLS certificate. The results of these
scans are available as large (about 35GB) CSV text files at

  https://scans_io/study/umich-https

Certscan is a utility program to work with these files.
Generally it's used to select entries from those files
based on some criterion, and loads a database with 
the certificates of interest for further queries.

Our primary interest is in certificates where the
certificate does not properly reflect the actual owner
of the domain.  Certificates with multiple, urelated
alternate domains warrant further examination.  So
the default for this program is to find certificates with
more than one second-level domain, and only load those.

To use this program:

1. Prequisites:
   - Linux was used, Windows will probably work.
   - Go 1.3 installed.
   - MySQL or equivalent installed.
   - Go/MySQL connector installed.
     (https://github.com/go-sql-driver/mysql/)
   - About 100GB of free disk space (for data)
   
2. Get the certificate data from "scans.io"
   https://scans.io/data/umich/https/certificates/certificates.csv.gz
   and unpack it.  
   This is about 12GB, and unpacks to about 36 GB.  So start that
   running while doing the rest of the steps.
   
3. Get the "public domain suffix list" from
   https://publicsuffix.org/list/effective_tld_names.dat
   This is a small file.
   
4. Create a Go code directory tree as is usual
   for Go, with environment variable GOPATH set
   to the root of the tree, and subdirectories
   "src", "bin", and "pkg" as is usual for Go.
   Put the contents of this Github project into
   "src", as "src/certscan". 
   
5. "go build certscan"

6. Create an account in MySQL, and create the
   tables in "certscan/sql/certscan.sql" in database "sslcerts".
   
7. Run
   ./certscan -user USER -pass PASS -database DATABASE -oidfile OIDFILE -tldfile TLDFILE CERTFILE
   
   where
   
   USER is the MySQL user name
   PASS is the MySQL password
   DATABASE is the MySQL database
   OIDFILE is the file in src/certscan/data/catypetable.csv
   TLDFILE is the public suffix file from step 3.
   CERTFILE is the big file unpacked in step 2.
   
   This will run for several hours, loading the database.
   
8, Try some queries.

SELECT * from certs WHERE Subject_commonname_2ld = "archive.org";

will display all certificates associated with "archive.org".

SELECT Subject_commonname_2ld, Subject_organization, certs.Issuer_name, capolicies.certlevel, count(DISTINCT Domain_2ld) AS count  
FROM certs, domains, policies, capolicies  
WHERE certs.Certificate_id = domains.Certificate_id  
AND policies.Certificate_id = certs.Certificate_id AND policies.OID = capolicies.OID 
AND Is_valid = TRUE AND Is_browser_valid = TRUE  
AND capolicies.certlevel = "EV" 
GROUP BY Subject_commonname_2ld,  Subject_organization, certs.Issuer_name, capolicies.certlevel 
ORDER BY count DESC LIMIT 100;

will provide a list of the top 100 Extended Validation certificates accepted by browsers with the most associated domain names.

Exploring the certificates associated with a given site is quick.
Complex queries such as the above are rather slow because of all the joins.  Worst case is about an hour. 

Note that the database is organized by second level domains (what registrars sell), and subdomains below that are ignored.

Enjoy exploring certificate land.


    John Nagle
    SiteTruth.com
    nagle@sitetruth.com
    October, 2014



