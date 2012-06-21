# CAS Perl Client

Jasig CAS client for Perl applications.

Author: Drew Mazurek

## Usage

To use, call the `AuthCasTest` program and enter a ticket that's valid for `$casService` below:

```perl
% ./AuthCasTest.pl
Login URL: https://localhost:8443/cas/login?TARGET=http://www.foo.com
Logout URL: https://localhost:8443/cas/logout?service=http://www.foo.com

AAFSsPYAkNKN6Mb0Q6Li8D8gawrtLIPuEh3v4JWafmP+FPpnAtt5g3jZ # YOU ENTER THIS!
Service ticket: AAFSsPYAkNKN6Mb0Q6Li8D8gawrtLIPuEh3v4JWafmP+FPpnAtt5g3jZ

User authenticated as mazurek
attr nickname = Drew
attr name = Drew Mazurek
attr id = mazurek
```