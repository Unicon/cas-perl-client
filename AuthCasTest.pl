#!/usr/bin/perl
#
# Just a script I used when I was testing out CAS... if it helps, by all
# means use it. Set the casUrl below, and then set the service itself
# in place of http://www.foo.com.
#
# To use, call the program and enter a ticket that's valid for $casService
# below:
#
#  % ./AuthCasTest.pl
#  Login URL: https://localhost:8443/cas/login?TARGET=http://www.foo.com
#  Logout URL: https://localhost:8443/cas/logout?service=http://www.foo.com
#  AAFSsPYAkNKN6Mb0Q6Li8D8gawrtLIPuEh3v4JWafmP+FPpnAtt5g3jZ <-- YOU ENTER THIS
#  Service ticket: AAFSsPYAkNKN6Mb0Q6Li8D8gawrtLIPuEh3v4JWafmP+FPpnAtt5g3jZ
#  User authenticated as mazurek
#  attr nickname = Drew
#  attr name = Drew Mazurek
#  attr id = mazurek
#


use strict;
use AuthCASSaml;

my $casUrl = "https://localhost:8443/cas";
my $casService = "http://www.foo.com";

my $cas = new AuthCASSaml(casUrl => $casUrl,
#			CAFile => '/home/mazurek/unicon/ku/ssl/server.jks');
			  saml => 1
);
my $login_url = $cas->getServerLoginURL($casService);

print "Login URL: $login_url\n";

my $logout_url = $cas->getServerLogoutURL($casService);

print "Logout URL: $logout_url\n";

my $ST = <>;

chomp $ST;

print "Service ticket: $ST\n";

if($cas->{saml}) {

    my %casResult = $cas->validateST($casService, $ST);

    if(!$casResult{user}) {
        print "invalid\n";
        printf STDERR "Error: %s\n", &AuthCASSaml::get_errors();
    } else {
        print "User authenticated as $casResult{user}\n";
        my $attrs = $casResult{attributes};
        if($attrs) {
	    foreach my $key (keys %$attrs) {
	        print "attr $key = $attrs->{$key}\n";
	    }
        } else {
	    print "no attributes\n";
        }
    }
} else {
    my $user = $cas->validateST($casService, $ST);
    print "User authenticated as $user\n";
}