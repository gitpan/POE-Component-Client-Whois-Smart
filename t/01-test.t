#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use POE;
use Data::Dumper;

# data for tests
my @domains = qw(     
    freshmeat.net
    freebsd.org
    reg.ru
    ns1.nameself.com.NS
    perl.com
);

my @domains_directi = map { "directi:$_" } qw(     
    freshmeat.net
    freebsd.org
    perl.com
    testazxcvawer.com
);


my @domains_not_reg = qw(
    thereisnosuchdomain123.com
    thereisnosuchdomain453.ru
    suxx.vn
);

my @ips = qw(
    202.75.38.179
    207.173.0.0
    87.242.73.95
);

my @registrars = ('REGRU-REG-RIPN');
my $server  = 'whois.ripn.net',

my $directi_requests_send;

# start test
plan tests => @domains + 2*@domains_directi + @domains_not_reg + @ips + @registrars + 1;

use_ok('POE::Component::Client::Whois::Smart');
print "The following tests requires internet connection...\n";

POE::Session->create(
    package_states => [
        'main' => [
                    qw(
                        _start
                        _response
                        _response_directi
                        _response_not_reg
                        _response_ip
                        _response_registrar
                    )
        ],
    ],
);

$poe_kernel->run();

sub _start {
    my ($kernel,$heap) = @_[KERNEL,HEAP]; 
    if ( 1 ) {
    POE::Component::Client::Whois::Smart->whois(
        query => \@domains,
        event => '_response',
	referral => 2,
	cache_dir => '/tmp/whois-gateway-d'
    );

    POE::Component::Client::Whois::Smart->whois(
        query  => \@registrars,
        server => $server, 
        event  => '_response_registrar',
    );
    }

    POE::Component::Client::Whois::Smart->whois(
        query  => \@domains_not_reg,
        event  => '_response_not_reg',
    );
    
    if ( 1 ) {
    POE::Component::Client::Whois::Smart->whois(
        query  => \@ips,
        event  => '_response_ip',
    );

    POE::Component::Client::Whois::Smart->whois(
        query  => \@domains_directi,
        event  => '_response_directi',
	directi_params => {
	    service_username => 'boldin.pavel@gmail.com',
	    service_password => 'dazachem',
	    service_langpref => 'en',
	    service_role     => 'reseller',
	    service_parentid => '999999998',
	    url		     => 'http://api.onlyfordemo.net/anacreon/servlet/APIv3',
	},
    );

    }
}

sub _response {
    my $full_result = $_[ARG0];
    foreach my $result ( @{$full_result} ) {
        my $query = $result->{query} if $result;
        $query =~ s/.NS$//i;

	#warn $result->{whois} if $query =~ m/perl.com/;

        ok( $result && !$result->{error} && $result->{whois} =~ /$query/i,
            "whois for domain ".$result->{query}." from ".$result->{server} );
    }                            

}

sub _response_directi {
    my $full_result = $_[ARG0];

    #warn Dumper \@_;

    foreach my $result ( @{$full_result} ) {
        my $query = $result->{query} if $result;
	my $ok;

	#use Data::Dumper;
	#warn Dumper $result;
	
	if ( $result->{whois} ) {
	  $ok  = $result->{whois} =~ m/^(available|regthrough)/;
	}
	else {
	    $ok = $result->{query} =~ m/\.(?:ru|ns)$/ && $result->{error};
	}
	$ok ||= $result->{error} eq 'Not found' && $query =~ m/^test/;

        ok( $ok, "whois for domain ".$result->{query}." from DirectI" );
    }                            

    if ( ! $directi_requests_send++ ) {
	POE::Component::Client::Whois::Smart->whois(
	    query  => \@domains_directi,
	    event  => '_response_directi',
	    directi_params => {
		service_username => 'boldin.pavel@gmail.com',
		service_password => 'dazachem',
		service_langpref => 'en',
		service_role     => 'reseller',
		service_parentid => '999999998',
		url		     => 'http://api.onlyfordemo.net/anacreon/servlet/APIv3',
	    },
	);
    }
}

sub _response_registrar {
    my $full_result = $_[ARG0];
    foreach my $result ( @{$full_result} ) {
        my $query = $result->{query} if $result;
	#print Dumper($result);


        ok( $result && !$result->{error} && $result->{whois} =~ /$query/i,
            "whois for registrar  ".$result->{query}." from ".$result->{server} );
    }                            
}

sub _response_not_reg {
    my $full_result = $_[ARG0];
    foreach my $result ( @{$full_result} ) {

        ok( $result && $result->{error},
            "whois for domain (not reged) ".$result->{query} );
    }                            
}

sub _response_ip {
    my $full_result = $_[ARG0];
    foreach my $result ( @{$full_result} ) {
        ok( $result && !$result->{error} && $result->{whois},
            "whois for IP ".$result->{query}." from ".$result->{server} );
    }                            
}

1;
