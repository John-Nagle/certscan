Certscan README

(Under development, not ready for use)

Utility programs for processing SSL/TLS dump files from U. Mich.

The security group at the University of Michigan periodically
examines every IPv4 address on the Internet to see if it
will return an SSL/TLS certificate. The results of these
scans are available as large (about 35GB) CSV text files at

  https://scans_io/study/umich-https

Certscan is a utility program to work with these files.
Generally it's used to select entries from those files
based on some criterion, and writes out a new CSV file
with fewer records for further processing with other
tools.

Our primary interest is in certificates where the
certificate does not properly reflect the actual owner
of the domain.  Certificates with multiple, urelated
alternate domains warrant further examination.


    John Nagle
    SiteTruth.com
    nagle@sitetruth.com
    October, 2014



