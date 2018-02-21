package AuthCASSaml;

use warnings;
use strict;
use XML::Simple;
use Date::Parse;
use POSIX qw(strftime);
use vars qw( $VERSION);

$VERSION = '1.0';

=head1 NAME

AuthCASSaml - Client library for CAS 2.0 authentication server, including support for SAML authentication with attributes.

=head1 VERSION

Version 1.0 (based on AuthCAS 1.5)

=head1 DESCRIPTION

AuthCASSaml aims at providing a Perl API to Yale's Central Authentication System (CAS). Only a basic Perl library is provided with CAS whereas AuthCAS is a full object-oriented library.

AuthCASSaml is based on Olivier Salaun's original AuthCAS library, with added SAML extensions for processing a CAS SAML assertion with attributes. Please note that proxy authentication is not supported by the CAS server if you enable SAML authentication.

=head1 PREREQUISITES

This script requires IO::Socket::SSL, LWP::UserAgent, XML::Simple, and Date::Parse.

=pod OSNAMES

any

=pod SCRIPT CATEGORIES

Network

=head1 SYNOPSIS

  A simple example with a direct CAS authentication

  use AuthCAS;
  my $cas = new AuthCAS(casUrl => 'https://cas.myserver, 
		    CAFile => '/etc/httpd/conf/ssl.crt/ca-bundle.crt',
		    );

  my $login_url = $cas->getServerLoginURL('http://myserver/app.cgi');

  ## The user should be redirected to the $login_url
  ## When coming back from the CAS server a ticket is provided in the QUERY_STRING

  ## $ST should contain the receaved Service Ticket
  my $user = $cas->validateST('http://myserver/app.cgi', $ST);

  printf "User authenticated as %s\n", $user;


  In the following example a proxy is requesting a Proxy Ticket for the target application

  $cas->proxyMode(pgtFile => '/tmp/pgt.txt',
	          pgtCallbackUrl => 'https://myserver/proxy.cgi?callback=1
		  );
  
  ## Same as before but the URL is the proxy URL
  my $login_url = $cas->getServerLoginURL('http://myserver/proxy.cgi');

  ## Like in the previous example we should receave a $ST

  my $user = $cas->validateST('http://myserver/proxy.cgi', $ST);

  ## Process errors
  printf STDERR "Error: %s\n", &AuthCAS::get_errors() unless (defined $user);

  ## Now we request a Proxy Ticket for the target application
  my $PT = $cas->retrievePT('http://myserver/app.cgi');
    
  ## This piece of code is executed by the target application
  ## It received a Proxy Ticket from the proxy
  my ($user, @proxies) = $cas->validatePT('http://myserver/app.cgi', $PT);

  printf "User authenticated as %s via %s proxies\n", $user, join(',',@proxies);

  ## SAML Example
  ##  samlTolerance is the number of seconds of allowed clock skew between
  ##  your application and the CAS server.
  my $cas = new AuthCAS(casUrl => 'https://cas.myserver, 
		    CAFile => '/etc/httpd/conf/ssl.crt/ca-bundle.crt',
		    saml => 1,
		    samlTolerance => 5
		    );

  ## This code is identical to non-SAML authentication
  my $login_url = $cas->getServerLoginURL('http://myserver/app.cgi');

  ## Note that the CAS result returned is now a hash.
  my %casResult = $cas->validateST('http://myserver/app.cgi', $ST);

  if($casResult{user}) {
    print "User authenticated as $casResult{user}\n";
    ## If there were any attributes, they're stored under the attributes key
    ## Note that this is a reference to the hash and must be treated as
    ## such.
    my $attrs = $casResult{attributes};
    if($attrs) {
      foreach my $key (keys %$attrs) {
        print "attr $key = $attrs->{$key}\n";
      }
    } else {
        print "no attributes\n";
    }
  } else {
    print "Invalid authentication event\n";
    printf STDERR "Error: %s\n", &AuthCASSaml::get_errors();
  }

=head1 DESCRIPTION

CAS is Jasig's web authentication system originally developed by
Yale University, and heavily inspired by Kerberos. Release 2.0 of CAS 
provides a "proxied credential" feature that allows authentication
tickets to be carried by intermediate applications (Portals for instance),
they are called proxy tickets.

This AuthCAS Perl module provides required subroutines to validate and 
retrieve CAS tickets.

=head1 SEE ALSO

Jasig Central Authentication Service (http://www.jasig.org/cas)
phpCAS (https://wiki.jasig.org/display/CASC/phpCAS)

=head1 COPYRIGHT

Copyright (C) 2003 Comite Reseau des Universites (http://www.cru.fr). All rights reserved.

Copyright (C) 2012 Unicon, Inc. (http://www.unicon.net)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHORS

Olivier Salaun
Drew Mazurek (SAML Extensions)

=cut

my @ISA = qw(Exporter);
my @EXPORT = qw($errors);

my $errors;

use Carp;

sub new {
    my($pkg, %param) = @_;
    my $cas_server = {};
    
    $cas_server->{'url'} = $param{'casUrl'};
    $cas_server->{'CAFile'} = $param{'CAFile'};
    $cas_server->{'CAPath'} = $param{'CAPath'};

    $cas_server->{'loginPath'} = $param{'loginPath'} || '/login';
    $cas_server->{'logoutPath'} = $param{'logoutPath'} || '/logout';
    $cas_server->{'serviceValidatePath'} = $param{'serviceValidatePath'} || '/serviceValidate';
    $cas_server->{'samlServiceValidatePath'} = $param{'samlServiceValidatePath'} || '/samlValidate';
    $cas_server->{'samlTolerance'} = $param{'samlTolerance'} || 1;
    $cas_server->{'proxyPath'} = $param{'proxyPath'} || '/proxy';
    $cas_server->{'proxyValidatePath'} = $param{'proxyValidatePath'} || '/proxyValidate';
    $cas_server->{'saml'} = $param{'saml'} || undef;

    bless $cas_server, $pkg;

    return $cas_server;
}

## Return module errors
sub get_errors {
    return $errors;
}

## Use the CAS object as a proxy
sub proxyMode {
    my $self = shift;
    my %param = @_;

    $self->{'pgtFile'} = $param{'pgtFile'};
    $self->{'pgtCallbackUrl'} = $param{'pgtCallbackUrl'};
    $self->{'proxy'} = 1;
    
    return 1;
}

## Escape dangerous chars in URLS
sub _escape_chars {
    my $s = shift;    

    ## Escape chars
    ##  !"#$%&'()+,:;<=>?[] AND accented chars
    ## escape % first
#    foreach my $i (0x25,0x20..0x24,0x26..0x2c,0x3a..0x3f,0x5b,0x5d,0x80..0x9f,0xa0..0xff) {
    foreach my $i (0x26) {
	my $hex_i = sprintf "%lx", $i;
	$s =~ s/\x$hex_i/%$hex_i/g;
    }

    return $s;
}

sub dump_var {
    my ($var, $level, $fd) = @_;
    
    if (ref($var)) {
	if (ref($var) eq 'ARRAY') {
	    foreach my $index (0..$#{$var}) {
		print $fd "\t"x$level.$index."\n";
		&dump_var($var->[$index], $level+1, $fd);
	    }
	}elsif (ref($var) eq 'HASH') {
	    foreach my $key (sort keys %{$var}) {
		print $fd "\t"x$level.'_'.$key.'_'."\n";
		&dump_var($var->{$key}, $level+1, $fd);
	    }    
	}
    }else {
	if (defined $var) {
	    print $fd "\t"x$level."'$var'"."\n";
	}else {
	    print $fd "\t"x$level."UNDEF\n";
	}
    }
}

## Parse an HTTP URL 
sub _parse_url {
    my $url = shift;

    my ($host, $port, $path);

    if ($url =~ /^(https?):\/\/([^:\/]+)(:(\d+))?(.*)$/) {
	$host = $2;
	$path = $5;
	if ($1 eq 'http') {
	    $port = $4 || 80;
	}elsif ($1 eq 'https') {
	    $port = $4 || 443;
	}else {
	    $errors = sprintf "Unknown protocol '%s'\n", $1;
	    return undef;
	}
    }else {
	$errors = sprintf "Unable to parse URL '%s'\n", $url;
	return undef;
    }

    return ($host, $port, $path);
}

## Simple XML parser
sub _parse_xml {
    my $data = shift;

    my %xml_struct;

    while ($data =~ /^<([^\s>]+)(\s+[^\s>]+)*>([\s\S\n]*)(<\/\1>)/m) {
	my ($new_tag, $new_data) = ($1,$3);
	chomp $new_data;
	$new_data =~ s/^[\s\n]+//m;
	$data =~ s/^<$new_tag(\s+[^\s>]+)*>([\s\S\n]*)(<\/$new_tag>)//m;
	$data =~ s/^[\s\n]+//m;
	
	## Check if data still includes XML tags
	my $struct;
	if ($new_data =~/^<([^\s>]+)(\s+[^\s>]+)*>([\s\S\n]*)(<\/\1>)/m) {
	    $struct = &_parse_xml($new_data);
	}else {
	    $struct = $new_data;
	}
	push @{$xml_struct{$new_tag}}, $struct;
    }
    
    return \%xml_struct;
}

sub getServerLoginURL {
    my $self = shift;
    my $service = shift;

    if($self->{'saml'}) { 
	return $self->{'url'}.$self->{'loginPath'}.'?TARGET='.&_escape_chars($service);
    } else {
	return $self->{'url'}.$self->{'loginPath'}.'?service='.&_escape_chars($service);
    }
}

## Returns non-blocking login URL
## ie: if user is logged in, return the ticket, otherwise do not prompt for login
sub getServerLoginGatewayURL {
    my $self = shift;
    my $service = shift;
    
    if($self->{'saml'}) { 
	return $self->{'url'}.$self->{'loginPath'}.'?TARGET='.&_escape_chars($service).'&gateway=1';;
    } else {
	return $self->{'url'}.$self->{'loginPath'}.'?service='.&_escape_chars($service).'&gateway=1';;
    }
}

## Return logout URL
## After logout user is redirected back to the application
sub getServerLogoutURL {
    my $self = shift;
    my $service = shift;
    
    return $self->{'url'}.$self->{'logoutPath'}.'?service='.&_escape_chars($service);
}

sub getServerServiceValidateURL {
    my $self = shift;
    my $service = shift;
    my $ticket = shift;
    my $pgtUrl = shift;

    my $query_string = 'service='.&_escape_chars($service).'&ticket='.$ticket;
    if (defined $pgtUrl) {
	$query_string .= '&pgtUrl='.&_escape_chars($pgtUrl);
    }

    ## URL was /validate with CAS 1.0
    return $self->{'url'}.$self->{'serviceValidatePath'}.'?'.$query_string;
}

sub getServerSamlServiceValidateURL {
    my $self = shift;
    my $service = shift;
    my $ticket = shift;
    my $pgtUrl = shift;

    #my $query_string = 'TARGET='.&_escape_chars($service).'&SAMLart='.$ticket;
    my $query_string = 'TARGET='.&_escape_chars($service);
    if (defined $pgtUrl) {
	$query_string .= '&pgtUrl='.&_escape_chars($pgtUrl);
    }

    return $self->{'url'}.$self->{'samlServiceValidatePath'}.'?'.$query_string;
}

sub getServerProxyURL {
    my $self = shift;
    my $targetService = shift;
    my $pgt = shift;

    return $self->{'url'}.$self->{'proxyPath'}.'?targetService='.&_escape_chars($targetService).'&pgt='.&_escape_chars($pgt);
}

sub getServerProxyValidateURL {
    my $self = shift;
    my $service = shift;
    my $ticket = shift;

    return $self->{'url'}.$self->{'proxyValidatePath'}.'?service='.&_escape_chars($service).'&ticket='.&_escape_chars($ticket);
     
}

sub validateSamlST {
    my $self = shift;
    my $service = shift;
    my $ticket = shift;
    my $pgtUrl = $self->{'pgtCallbackUrl'};

    my $samlBody = buildSamlBody($self,$ticket);

    my $samlXml = &XMLin($self->callCAS($self->getServerSamlServiceValidateURL($service, $ticket, $pgtUrl),$samlBody));

    my $responseBase = $samlXml->{'SOAP-ENV:Body'}{'Response'};

    my $statusCode = $responseBase->{'Status'}{'StatusCode'}{'Value'};

    if($statusCode eq "samlp:Success") {

	# first validate timestamp (tolerance in seconds)
	my $tolerance = $self->{'samlTolerance'} || 5;

	my $now = time();
	my $conditions = $responseBase->{'Assertion'}{'Conditions'};
	if(!defined $conditions) {
	    # error message
	    $errors = "No time condition found in response. Invalid.";
	    return undef;
	}
	my $notOnOrAfter = str2time($conditions->{'NotOnOrAfter'});
	my $notBefore = str2time($conditions->{'NotBefore'});

	if($now + $tolerance < $notBefore) {
	    $errors = "Assertion not yet valid. Check CAS and local server times or adjust the samlTolerance parameter.\n";
	    return undef;
	}

	if($now - $tolerance >= $notOnOrAfter) {
	    $errors = "Assertion expired. Check CAS and local server times or adjust the samlTolerance parameter.\n";
	    return undef;
	}

	my $user = $responseBase->{'Assertion'}{'AuthenticationStatement'}{'Subject'}{'NameIdentifier'};
	my %casAttrs;
	my $attrs = $responseBase->{'Assertion'}{'AttributeStatement'}{'Attribute'};
	if($attrs) {
	    for(my $i=0;$i<@$attrs;$i++) {
		my $attr = $$attrs[$i];
		my $name = $attr->{'AttributeName'};
		my $value = $attr->{'AttributeValue'};
		$casAttrs{$name} = $value;
	    }
	}

	my %result;
	$result{'user'} = $user;
	$result{'attributes'} = \%casAttrs;
	return %result;
    } else {
	$errors = "Invalid SAML assertion ($responseBase->{'Status'}{'StatusMessage'})\n";
	return undef;
    }
}

## Validate a Service Ticket
## Also used to get a PGT
sub validateST {

    my $self = shift;
    my $service = shift;
    my $ticket = shift;

    if(defined $self->{'saml'}) {
	return validateSamlST($self,$service,$ticket);
    }

    my $pgtUrl = $self->{'pgtCallbackUrl'};
    
    my $xml = &_parse_xml($self->callCAS($self->getServerServiceValidateURL($service, $ticket, $pgtUrl)));

    if (defined $xml->{'cas:serviceResponse'}[0]{'cas:authenticationFailure'}) {
	$errors = sprintf "Failed to validate Service Ticket %s : %s\n", $ticket, $xml->{'cas:serviceResponse'}[0]{'cas:authenticationFailure'}[0];
	return undef;
    }

    my $user = $xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:user'}[0];

    ## If in Proxy mode, also retreave a PGT
    if ($self->{'proxy'}) {
	my $pgtIou;
	if (defined $xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:proxyGrantingTicket'}) {
	    $pgtIou = $xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:proxyGrantingTicket'}[0];
	}
	
	unless (defined $self->{'pgtFile'}) {
	    $errors = sprintf "pgtFile not defined\n";
	    return undef;
	}

	## Check stored PGT
	unless (open STORE, $self->{'pgtFile'}) {
	    $errors = sprintf "Unable to read %s\n", $self->{'pgtFile'};
	    return undef;
	}
	
	my $pgtId;
	while (<STORE>) {
	    if (/^$pgtIou\s+(.+)$/) {
		$pgtId = $1;
		last;
	    }
	}
	
	$self->{'pgtId'} = $pgtId;
    }

    return ($user);
}

## Validate a Proxy Ticket
sub validatePT {
    my $self = shift;
    my $service = shift;
    my $ticket = shift;

    my $xml = &_parse_xml($self->callCAS($self->getServerProxyValidateURL($service, $ticket)));

    if (defined $xml->{'cas:serviceResponse'}[0]{'cas:authenticationFailure'}) {
	$errors = sprintf "Failed to validate Proxy Ticket %s : %s\n", $ticket, $xml->{'cas:serviceResponse'}[0]{'cas:authenticationFailure'}[0];
	return undef;
    }

    my $user = $xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:user'}[0];
    
    my @proxies;
    if (defined $xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:proxies'}) {
	@proxies = @{$xml->{'cas:serviceResponse'}[0]{'cas:authenticationSuccess'}[0]{'cas:proxies'}[0]{'cas:proxy'}};
    }

    return ($user, @proxies);
}

## Access a CAS URL and parses received XML
sub callCAS {
    my $self = shift;
    my $url = shift;
    my $body = shift;

    my ($host, $port, $path) = &_parse_url($url);
    
    my @xml = &get_https2($host, $port, $path,{'cafile' =>  $self->{'CAFile'},  'capath' => $self->{'CAPath'}},$body);

    unless (@xml) {
	warn $errors;
	return undef;
    }

    ## Skip HTTP header fields
    my $line = shift @xml;
    while ($line !~ /^\s*$/){
	$line = shift @xml;
    }

    return join('',@xml);
}

sub storePGT {
    my $self = shift;
    my $pgtIou = shift;
    my $pgtId = shift;
    
    unless (open STORE, ">>$self->{'pgtFile'}") {
	$errors = sprintf "Unable to write to %s\n", $self->{'pgtFile'};
	return undef;
    }
    printf STORE "%s\t%s\n", $pgtIou, $pgtId;
    close STORE;

    return 1;
}


sub retrievePT {
    my $self = shift;
    my $service = shift;

    my $xml = &_parse_xml($self->callCAS($self->getServerProxyURL($service, $self->{'pgtId'})));

    if (defined $xml->{'cas:serviceResponse'}[0]{'cas:proxyFailure'}) {
	$errors = sprintf "Failed to get PT : %s\n", $xml->{'cas:serviceResponse'}[0]{'cas:proxyFailure'}[0];
	return undef;
    }

    if (defined $xml->{'cas:serviceResponse'}[0]{'cas:proxySuccess'}[0]{'cas:proxyTicket'}) {
	return $xml->{'cas:serviceResponse'}[0]{'cas:proxySuccess'}[0]{'cas:proxyTicket'}[0];
    }

    return undef;
}

# request a document using https, return status and content
sub get_https2{
	my $host = shift;
	my $port = shift;
	my $path = shift;

	my $ssl_data= shift;
	my $body = shift;

	my $trusted_ca_file = $ssl_data->{'cafile'};
	my $trusted_ca_path = $ssl_data->{'capath'};

	if (($trusted_ca_file && !(-r $trusted_ca_file)) ||  
		 ($trusted_ca_path && !(-d $trusted_ca_path))) {
	    $errors = sprintf "error : incorrect access to cafile $trusted_ca_file or capath $trusted_ca_path\n";
	    return undef;
	}
	
	unless (eval "require IO::Socket::SSL") {
	    $errors = sprintf "Unable to use SSL library, IO::Socket::SSL required, install IO-Socket-SSL (CPAN) first\n";
	    return undef;
	}
	require IO::Socket::SSL;

	unless (eval "require LWP::UserAgent") {
	    $errors = sprintf "Unable to use LWP library, LWP::UserAgent required, install LWP (CPAN) first\n";
	    return undef;
	}
	require  LWP::UserAgent;

	my $ssl_socket;

	my %ssl_options = (SSL_use_cert => 0,
			   PeerAddr => $host,
			   PeerPort => $port,
			   Proto => 'tcp',
			   Timeout => '5'
			   );

	$ssl_options{'SSL_ca_file'} = $trusted_ca_file if ($trusted_ca_file);
	$ssl_options{'SSL_ca_path'} = $trusted_ca_path if ($trusted_ca_path);
	
	## If SSL_ca_file or SSL_ca_path => verify peer certificate
	$ssl_options{'SSL_verify_mode'} = 0x01 if ($trusted_ca_file || $trusted_ca_path);
	
	$ssl_socket = new IO::Socket::SSL(%ssl_options);
	
	unless ($ssl_socket) {
	    $errors = sprintf "error %s unable to connect https://%s:%s/\n",&IO::Socket::SSL::errstr,$host,$port;
	    return undef;
	}
	
	my $request;
	if (defined $body) {
	    my $length = length $body;
		 $request = "POST $path HTTP/1.0\r\nHost: $host\r\nContent-Length: $length\r\nContent-Type: text/xml\r\n\r\n$body";
	} else {
 	    $request = "GET $path HTTP/1.0\r\nHost: $host\r\n\r\n";
	}

	print $ssl_socket "$request";

	my @result;
	while (my $line = $ssl_socket->getline) {
	    push  @result, $line;
	} 

	$ssl_socket->close(SSL_no_shutdown => 1);	

	return (@result);
}

# Brute force. Based largely on Java CAS client.
sub buildSamlBody {
    my $self = shift;
    my $ticket = shift;
    my $requestId = generateSamlId(32);
    my $now = time();
    my $iso8601Time = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime($now));

    my $samlBody = '<SOAP-ENV:Envelope '
	. 'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
	. '<SOAP-ENV:Header/><SOAP-ENV:Body>'
	. '<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"'
	. 'MajorVersion="1" MinorVersion="1" RequestID="' . $requestId
	. '" IssueInstant="' . $iso8601Time . '"><samlp:AssertionArtifact>' 
	. $ticket . '</samlp:AssertionArtifact></samlp:Request>'
	. '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

    return $samlBody;
}

sub generateSamlId {
    my $length = shift;

    my @chars = ('A'..'Z','a'..'z','0'..'9');
    my $id;

    for(my $i=0;$i<$length;$i++) {
	$id .= $chars[rand @chars];
    }

    return $id
}

1;

