#!/usr/bin/perl -w
use strict;
use Module::Build;

my $build = Module::Build->new(
    module_name => 'POE::Component::Client::Whois::Smart',
    license  => 'perl',
    requires => {
        'POE' => 0,
	'POE::Filter::Line' => 0,
	'POE::Wheel::ReadWrite' => 0,
	'POE::Wheel::SocketFactory' => 0,
	'POE::Component::Client::HTTP' => 0,
        'Net::Netmask' => 0,        
    },
    create_makefile_pl => 'traditional',
);
$build->create_build_script;
