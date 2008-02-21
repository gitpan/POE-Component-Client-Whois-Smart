package POE::Component::Client::Whois::Smart;

use strict;
use warnings;
use Socket;
use POE qw(Filter::Line Wheel::ReadWrite Wheel::SocketFactory Component::Client::HTTP);
use POE::Component::Client::Whois::Smart::Data;
use HTTP::Request;
#use Data::Dumper;

our $VERSION = '0.07';
our $DEBUG;
our @local_ips = ();
our %servers_ban = ();
#our $rism_all; # = Request per Ip per Server per Minute =)

# init whois query 
sub whois {
    my $class = shift;
    my %args = @_;

    $args{session} = $args{session} || $poe_kernel->get_active_session();        
    
    POE::Session->create(
        inline_states => {
            _start      => \&_start_manager,
            _query_done => \&_query_done,
        },
        args => [ \%args ],
    );
  
    undef;
}

# start manager, which manages all process and returns result to caller 
sub _start_manager {
    my ($heap, $session, $arg_ref) = @_[HEAP, SESSION, ARG0];
    my %args = %$arg_ref;
    
    $args{referral} = 1 unless defined $args{referral};
    $heap->{params}->{referral}    = $args{referral};
    $heap->{params}->{event}       = delete $args{event};
    $heap->{params}->{session}     = delete $args{session};
    $heap->{params}->{use_cnames}  = delete $args{use_cnames};
    $heap->{params}->{cache_dir}   = $args{cache_dir};
    $heap->{params}->{cache_time}  = $args{cache_time} ||= 1;
    $heap->{params}->{omit_msg}
        = defined $args{omit_msg} ? delete $args{omit_msg} : 0;
    $heap->{params}->{exceed_wait}
        = defined $args{exceed_wait} ? $args{exceed_wait} : 0;
    

    $args{host}       = delete $args{server},
    $args{manager_id} = $session->ID();
    $args{event}      = "_query_done";
    $args{timeout}    = $args{timeout} || 30;
    
    $heap->{tasks}    = 0;
    
    @local_ips = @{$args{local_ips}}
        if $args{local_ips}
            && (join '', sort @local_ips) ne (join '', sort @{$args{local_ips}});
    
    delete $args{local_ips};


    my (@query_list) = @{$args{query}};
    delete $args{query};  

    foreach my $query (@query_list) {        
        $heap->{tasks}++;
        $args{query}          = lc $query;
        $args{original_query} = lc $query;
        __PACKAGE__->get_whois(%args);
    }
    
    undef;
}

# caches retrieved whois-info, return result if no more tasks
sub _query_done {
    my ($kernel, $heap, $session, $response) = @_[KERNEL, HEAP, SESSION, ARG0];

    my ($whois, $error);
    if ($response->{from_cache}) {
        $whois = $response->{whois};
        #$heap->{tasks}--;
    } elsif ($response->{host} eq "http") {
        $whois = $response->{whois};
        $error = $response->{error};
    } else {
        $whois = defined $response->{reply} ? join "\n", @{$response->{reply}} : "";
        delete $response->{reply};
        ($whois, $error) = process_whois(
            $response->{original_query},
            $response->{host},
            $whois,
            $heap->{params}
        );
    }
    
    # exceed
    if ($error && $error eq 'Connection rate exceeded') {
        my $current_ip = $response->{local_ip} || 'localhost';
        $servers_ban{$response->{host}}->{$current_ip} = time;
        print "Connection rate exceeded for IP: $current_ip, server: "
            .$response->{host}."\n"
                if $DEBUG;
            
        if ($heap->{params}->{exceed_wait}) {
            my %args = %$response;
            delete $args{local_ip};
            delete $args{error};
            delete $args{whois};            
            $args{manager_id} = $session->ID();
            __PACKAGE__->get_whois(%args);
            return undef;
        }
    }
    
    
    $heap->{tasks}--;
    
    if (!$error || !$heap->{result}->{$response->{original_query}}) {
        my %result = (
            query      => $response->{query},
            server     => $response->{host},
            query_real => $response->{query_real},
            whois      => $whois,
            error      => $error,
            from_cache => $response->{from_cache},
        );
        
        push @{ $heap->{result}->{$response->{original_query}} }, \%result;
    
        my ($new_server, $new_query) = get_recursion(
            $result{whois},
            $result{server},
            $result{query},
            @{ $heap->{result}->{$response->{original_query}} },    
        ) if $heap->{params}->{referral} && $response->{host} ne "http";
        
        if ($new_server && !$result{from_cache}) {
            my %args = %$response;
            delete $args{reply};
            
            $args{manager_id}  = $session->ID();
            $args{event}       = "_query_done";
            $args{query}       = $new_query;
            $args{host}        = $new_server;
        
            $heap->{tasks}++;
            __PACKAGE__->get_whois(%args);
        }
    }
    
    unless ($heap->{tasks}) {     
        my @result;
        foreach my $query (keys %{$heap->{result}}) {            
            my %res = (
                query  => $heap->{result}->{$query}->[-1]->{query},
                whois  => $heap->{result}->{$query}->[-1]->{whois},
                server => $heap->{result}->{$query}->[-1]->{server},
                error  => $heap->{result}->{$query}->[-1]->{error},                
            );
            
            write_to_cache(%res, $heap->{params}->{cache_dir})
                if $heap->{params}->{cache_dir} && !$res{from_cache};
            
            $res{subqueries} = $heap->{result}->{$query}
                if $heap->{params}->{referral} == 2;
            
            push @result, \%res;
        }
        
        $kernel->post( $heap->{params}->{session},
            $heap->{params}->{event}, \@result )
    }
    
    undef;
}

# get whois-server and start socket or http session
sub get_whois {
    my $package = shift;
    my %args = @_;

    $args{lc $_} = delete $args{$_} for keys %args;

    unless ( $args{host} ) {
        my $whois_server;
        my $ips = POE::Component::Client::Whois::Smart::Data->new();
        SWITCH: {
            if (is_ipaddr($args{query})) {
                $whois_server = ( $ips->get_ip_server( $args{query} ) )[0];
                unless ( $whois_server ) {
                    warn "Couldn\'t determine correct whois server, falling back on arin\n"
                        if $DEBUG;
                    $whois_server = 'whois.arin.net';
                }
                last SWITCH;
            }
            if (is_ip6addr($args{query})) {
                warn "IPv6 detected, defaulting to 6bone\n";
                $whois_server = 'whois.6bone.net';
                last SWITCH;
            }
            $whois_server = get_server($args{query}, $args{params}->{use_cnames});
            unless ( $whois_server ) {
                warn "Could not determine whois server from query string, defaulting to internic \n";
                $whois_server = 'whois.internic.net';
            }
        }
        $args{host} = $whois_server;
    }

    $args{query_real} = $args{query};
    
    unless ($args{host} eq "http") {
        $args{query_real} =~ s/.NS$//i;
        if ($args{host} eq 'whois.crsnic.net') {
            $args{query_real} = "domain ".$args{query_real};
        } elsif ($args{host} eq 'whois.denic.de') {
            $args{query_real} = "-T dn,ace -C ISO-8859-1 ".$args{query_real};
        } elsif ($args{host} eq 'whois.nic.name') {
            $args{query_real} = "domain=".$args{query_real};
        }
    }

    my $self = bless { request => \%args }, $package;

    $self->{session_id} = POE::Session->create(
        object_states => [ 
            $self => [
                qw( _start _connect _connect_http _http_down
                    _sock_input _sock_down _sock_up _sock_failed _time_out)
            ],
        ],
        options => { trace => 0 },
    )->ID();

    return $self;
}


# init session
sub _start {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    $self->{session_id} = $_[SESSION]->ID();
    
    if ($self->{request}->{cache_dir} && $self->{request}->{referral} == 1) {
        my ($whois, $server) = get_from_cache(
            $self->{request}->{query},
            $self->{request}->{cache_dir},
            $self->{request}->{cache_time},            
        );
        if ($whois) {            
            my $request = delete $self->{request};
            my $session = delete $request->{manager_id};
            
            $request->{whois}      = $whois;
            $request->{host}       = $server;
            $request->{from_cache} = 1;
            $kernel->post( $session => $request->{event} => $request );
            
            return undef;
        }
    }
    
    if ($self->{request}->{host} eq "http") {
        $kernel->yield( '_connect_http' );
    } else {
        $kernel->yield( '_connect' );
    }
  
    undef;
}

# connects to whois-server (socket)
sub _connect {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    my $local_ip = next_local_ip(
        $self->{request}->{host},
        $self->{request}->{clientname},
        $self->{request}->{rism},
    );
    
    
    unless ($local_ip) {
        my $unban_time = unban_time(
            $self->{request}->{host},
            $self->{request}->{clientname},
            $self->{request}->{rism},                        
        );
        my $delay_err = $kernel->delay_add('_connect', $unban_time);
        print "All IPs banned for server ".$self->{request}->{host}.
            ", waiting: $unban_time sec\n"
                if $DEBUG;
        return undef;
    }
    
    print "Query '".$self->{request}->{query_real}.
        "' to ".$self->{request}->{host}.
        " from $local_ip\n"
            if $DEBUG;
    
    $local_ip = undef if $local_ip eq 'localhost';
    
    $self->{factory} = POE::Wheel::SocketFactory->new(
        SocketDomain   => AF_INET,
        SocketType     => SOCK_STREAM,
        SocketProtocol => 'tcp',
        RemoteAddress  => $self->{request}->{host},
        RemotePort     => $self->{request}->{port} || 43,
        BindAddress    => $local_ip,
        SuccessEvent   => '_sock_up',
        FailureEvent   => '_sock_failed',
    );
    
    undef;
}

# connects to whois-server (http)
sub _connect_http {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    POE::Component::Client::HTTP->spawn(
        Alias => 'ua',
        Timeout => $self->{timeout},
    );
    
    my $curl;    
    my ($url, $tld, %form) = get_http_query_url($self->{request}->{query});        
    $self->{request}->{tld} = $tld;
    my $method = scalar(keys %form) ? 'POST' : 'GET';
    
    my $req = new HTTP::Request $method, $url;
    
    if ($method eq 'POST') {
        $curl = url("http:");
        $req->content_type('application/x-www-form-urlencoded');
        $curl->query_form(%form);
        $req->content($curl->equery);
    }
    
    $kernel->post("ua", "request", "_http_down", $req);
    
    undef;
}

# cach result from http whois-server
sub _http_down {
    my ($kernel, $heap, $self, $request_packet, $response_packet)
	= @_[KERNEL, HEAP, OBJECT, ARG0, ARG1];

    # response obj
    my $response = $response_packet->[0];    
    # response content
    my $content  = $response->content();
    
    $self->{request}->{whois}
        = parse_www_content($content, $self->{request}->{tld});
    
    my $request = delete $self->{request};
    my $session = delete $request->{manager_id};

    if ($request->{whois}) {
        delete $request->{error};
    } else {
        $request->{error} = "No information";
    }
    $kernel->post( $session => $request->{event} => $request );
    
    undef;
}

# socket error
sub _sock_failed {
    my ($kernel, $self, $op, $errno, $errstr) = @_[KERNEL, OBJECT, ARG0..ARG2];

    delete $self->{factory};
    $self->{request}->{error} = "$op error $errno: $errstr";
    my $request = delete $self->{request};
    my $session = delete $request->{manager_id};

    $kernel->post( $session => $request->{event} => $request );
    
    undef;
}

# connection with socket established, send query
sub _sock_up {
    my ($kernel, $self, $session, $socket) = @_[KERNEL, OBJECT, SESSION, ARG0];
    delete $self->{factory};

    $self->{'socket'} = new POE::Wheel::ReadWrite(
        Handle     => $socket,
        Driver     => POE::Driver::SysRW->new(),
        Filter     => POE::Filter::Line->new( InputRegexp => '\015?\012',
                                            OutputLiteral => "\015\012" ),
        InputEvent => '_sock_input',
        ErrorEvent => '_sock_down',
    );

    unless ( $self->{'socket'} ) {
        my $request = delete $self->{request};
        my $session = delete $request->{manager_id};
        $request->{error} = "Couldn\'t create a Wheel::ReadWrite on socket for whois";
        $kernel->post( $session => $request->{event} => $request );
        
        return undef;
    }

    $self->{'socket'}->put( $self->{request}->{query_real} );
    $kernel->delay( '_time_out' => $self->{timeout});
    
    undef;
}

# connection with socket finished, post result to manager
sub _sock_down {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    delete $self->{socket};
    $kernel->delay( '_time_out' => undef );

    my $request = delete $self->{request};
    my $session = delete $request->{manager_id};

    if ( defined ( $request->{reply} ) and ref( $request->{reply} ) eq 'ARRAY' ) {
        delete $request->{error};
    } else {
        $request->{error} = "No information received from remote host";
    }
    $kernel->post( $session => $request->{event} => $request );
    
    undef;
}

# got input from socket, save it
sub _sock_input {
    my ($kernel,$self,$line) = @_[KERNEL,OBJECT,ARG0];
    push @{ $self->{request}->{reply} }, $line;
    
    undef;
}

# socket timeout, abort connection
sub _time_out {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    delete $self->{'socket'};
  
    undef;
}

# check whois-info, if it has referrals, return new server and query
sub get_recursion {
    my ($whois, $server, $query, @prev_results) = @_;

    my ($new_server, $registrar);
    my $new_query  = $query;
    
    foreach (split "\n", $whois) {
    	$registrar ||= /Registrar/ || /Registered through/;
            
    	if ($registrar && /Whois Server:\s*([A-Za-z0-9\-_\.]+)/) {
            $new_server = lc $1;
            #last;
    	} elsif ($whois =~ /To single out one record, look it up with \"xxx\",/s) {
            $new_server = $server;
            $new_query  = "=$query";
            last;
	} elsif (/ReferralServer: whois:\/\/([-.\w]+)/) {
	    #warn "SEX!!!!\n";
	    $new_server = $1;
	    last;
	} elsif (/Contact information can be found in the (\S+)\s+database/) {
	    $new_server = $POE::Component::Client::Whois::Smart::Data::ip_whois_servers{ $1 };
            #last;
    	} elsif ((/OrgID:\s+(\w+)/ || /descr:\s+(\w+)/) && is_ipaddr($query)) {
	    my $value = $1;	
	    if($value =~ /^(?:RIPE|APNIC|KRNIC|LACNIC)$/) {
		$new_server = $POE::Component::Client::Whois::Smart::Data::ip_whois_servers{$value};
		last;
	    }
    	} elsif (/^\s+Maintainer:\s+RIPE\b/ && is_ipaddr($query)) {
            $new_server = $POE::Component::Client::Whois::Smart::Data::servers{RIPE};
            last;
	}
    }
    
    if ($new_server) {
        foreach my $result (@prev_results) {
            return undef if $result->{query} eq $new_query
                && $result->{server} eq $new_server;
        }
    }
    
    return $new_server, $new_query;
}

# get whois-server for domain
sub get_server {
    my ($dom, $use_cnames) = @_;

    my $tld = uc get_dom_tld( $dom );
    $tld =~ s/^XN--(\w)/XN---$1/;

    if (grep { $_ eq $tld } @POE::Component::Client::Whois::Smart::Data::www_whois) {
       return 'http';
    }

    my $cname = "$tld.whois-servers.net";

    my $srv = $POE::Component::Client::Whois::Smart::Data::servers{$tld} || $cname;
    $srv = $cname if $use_cnames && gethostbyname($cname);

    return $srv;
}

# get domain TLD
sub get_dom_tld {
    my ($dom) = @_;

    my $tld;
    if (is_ipaddr($dom)) {
        $tld = "IP";
    } elsif (domain_level($dom) == 1) {
        $tld = "NOTLD";
    } else { 
        my @alltlds = keys %POE::Component::Client::Whois::Smart::Data::servers;
        @alltlds = sort { dlen($b) <=> dlen($a) } @alltlds;
        foreach my $awailtld (@alltlds) {
            $awailtld = lc $awailtld;
            if ($dom =~ /(.+?)\.($awailtld)$/) {
                $tld = $2;
                last;
            }
        }
        unless ($tld) {
            my @tokens = split(/\./, $dom);
            $tld = $tokens[-1]; 
        }
    }

    return $tld;
}

# get domain level
sub domain_level {
    my ($str) = @_;
    my $dotcount = $str =~ tr/././;
    return $dotcount + 1;
}

#
sub dlen {
    my ($str) = @_;
    return length($str) * domain_level($str);
}

# check, is it IP-address?
sub is_ipaddr {
    $_[0] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}

# check, is it IPv6-address?
sub is_ip6addr {
    # TODO: bad implementation!!!!!
    $_[0] =~ /:/;
}

# chech if Connection rate exceeded, if whois info found, strip copyrights
sub process_whois {
    my ($query, $server, $whois, $params) = @_;

    if (!is_ipaddr($query) && !is_ip6addr($query)) {
        $server = lc $server;
        my ($name, $tld) = split_domain($query);
    
        if ($tld eq 'mu') {
            if ($whois =~ /.MU Domain Information\n(.+?\n)\n/s) {
                $whois = $1;
            }
        }
    
        my $exceed = $POE::Component::Client::Whois::Smart::Data::exceed{$server};
        if ($exceed && $whois =~ /$exceed/s) {
            return $whois, "Connection rate exceeded";
        }
    
        my %notfound = %POE::Component::Client::Whois::Smart::Data::notfound;
        my %strip = %POE::Component::Client::Whois::Smart::Data::strip;
    
        my $notfound = $notfound{$server};
        my @strip = $strip{$server} ? @{$strip{$server}} : ();
        my @lines;
        MAIN: foreach (split(/\n/, $whois)) {
            if ($notfound && /$notfound/) {
                return $whois, "Not found";
            };
            if ($params->{omit_msg}) {
                foreach my $re (@strip) {
                    next MAIN if (/$re/);
                }
            }
            push(@lines, $_);
        }
    
        $whois = join("\n", @lines, "");
        $whois = strip_whois($whois) if $params->{omit_msg} > 1;
    
        return $whois, "Not found" unless check_existance($whois);
    }
    
    return $whois, undef;
}

# split domain on name and TLD
sub split_domain {
    my ($dom) = @_;

    my $tld = get_dom_tld( $dom );

    my $name;
    if (uc $tld eq 'IP' || $tld eq 'NOTLD') {
	$name = $dom;
    } else {
	$dom =~ /(.+?)\.$tld$/; # or die "Can't match $tld in $dom";
	$name = $1;
    }

    return ($name, $tld);
}

#  check if whois info found
sub check_existance {
    $_ = $_[0];

    return undef if
        /is unavailable/is ||
        /No entries found for the selected source/is ||
        /Not found:/s ||
        /No match\./s ||
        /is available for/is ||
        /Not found/is &&
            !/ your query returns "NOT FOUND"/ &&
            !/Domain not found locally/ ||
        /No match for/is ||
        /No Objects Found/s ||
        /No domain records were found/s ||
        /No such domain/s ||
        /No entries found in the /s ||
        /Could not find a match for/s ||
        /Unable to find any information for your query/s ||
        /is not registered/s ||
        /no matching record/s ||
	/No match found\n/ ||
        /NOMATCH/s;

    return 1;
}

sub strip_whois {
    $_ = $_[0];

    s/The Data.+(policy|connection)\.\n//is;
    s/% NOTE:.+prohibited\.//is;
    s/Disclaimer:.+\*\*\*\n?//is;
    s/NeuLevel,.+A DOMAIN NAME\.//is;
    s/For information about.+page=spec//is;
    s/NOTICE: Access to.+this policy.//is;
    s/The previous information.+completeness\.//s;
    s/NOTICE AND TERMS OF USE:.*modify these terms at any time\.//s;
    s/TERMS OF USE:.*?modify these terms at any time\.//s;
    s/NOTICE:.*for this registration\.//s;

    s/By submitting a WHOIS query.+?DOMAIN AVAILABILITY.\n?//s;
    s/Registration and WHOIS.+?its accuracy.\n?//s;
    s/Disclaimer:.+?\*\*\*\n?//s;
    s/The .COOP Registration .+ Information\.//s;
    s/Whois Server Version \d+\.\d+.//is;
    s/NeuStar,.+www.whois.us\.//is;
    s/\n?Domain names in the \.com, .+ detailed information.\n?//s;
    s/\n?The Registry database .+?Registrars\.\n//s;
    s/\n?>>> Last update of .+? <<<\n?//;
    s/% .+?\n//gs;
    s/Domain names can now be registered.+?for detailed information.//s;

    s/^\n+//s;
    s/(?:\s*\n)+$/\n/s;

    $_;
}

# get URL for query via HTTP
# %param: domain*
sub get_http_query_url {
    my ($domain) = @_;    
    
    my ($name, $tld) = split_domain($domain);
    my ($url, %form);

    if ($tld eq 'tv') {
        $url = "http://www.tv/cgi-bin/whois.cgi?domain=$name&tld=tv";
    } elsif ($tld eq 'mu') {
        $url = 'http://www.mu/cgi-bin/mu_whois.cgi';
        $form{whois} = $name;
    } elsif ($tld eq 'spb.ru' || $tld eq 'msk.ru') {
        $url = "http://www.relcom.ru/Services/Whois/?fullName=$name.$tld";
    } elsif ($tld eq 'ru' || $tld eq 'su') {
        $url = "http://www.nic.ru/whois/?domain=$name.$tld";
    } elsif ($tld eq 'ip') {
        $url = "http://www.nic.ru/whois/?ip=$name";
    } elsif ($tld eq 'in') {
        $url = "http://www.registry.in/cgi-bin/whois.cgi?whois_query_field=$name";
    } elsif ($tld eq 'cn') {
        $url = "http://ewhois.cnnic.net.cn/whois?value=$name.$tld&entity=domain";
    } elsif ($tld eq 'ws') {
        $url = "http://worldsite.ws/utilities/lookup.dhtml?domain=$name&tld=$tld";
    } elsif ($tld eq 'kz') {
        $url = "http://www.nic.kz/cgi-bin/whois?query=$name.$tld&x=0&y=0";
    } else {
        return 0;
    }
        
    return $url, $tld, %form;
}

# Parse content received from HTTP server
# %param: resp*, tld*
sub parse_www_content {
    my ($resp, $tld) = @_;
    
    # below untached from Net::Whois::Raw
    chomp $resp;
    $resp =~ s/\r//g;

    my $ishtml;

    if ($tld eq 'tv') {

        return 0 unless
        $resp =~ /(<TABLE BORDER="0" CELLPADDING="4" CELLSPACING="0" WIDTH="95%">.+?<\/TABLE>)/is;
        $resp = $1;
        $resp =~ s/<BR><BR>.+?The data in The.+?any time.+?<BR><BR>//is;
        return 0 if $resp =~ /Whois information is not available for domain/s;
        $ishtml = 1;

    } elsif ($tld eq 'spb.ru' || $tld eq 'msk.ru') {

        $resp = _koi2win( $resp );
        return undef unless $resp =~ m|<TABLE BORDER="0" CELLSPACING="0" CELLPADDING="2"><TR><TD BGCOLOR="#990000"><TABLE BORDER="0" CELLSPACING="0" CELLPADDING="20"><TR><TD BGCOLOR="white">(.+?)</TD></TR></TABLE></TD></TR></TABLE>|s;
        $resp = $1;

        return 0 if $resp =~ m/СВОБОДНО/;

        if ($resp =~ m|<PRE>(.+?)</PRE>|s) {
            $resp = $1;
        } elsif ($resp =~ m|DNS \(name-серверах\):</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE><H3>Дополнительную информацию можно получить по адресу:</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE>|) {
            my $nameservers = $1;
            my $emails = $2;
            my (@nameservers, @emails);
            while ($nameservers =~ m|<CODE CLASS="h2black">(.+?)</CODE>|g) {
                push @nameservers, $1;
            }
            while ($emails =~ m|<CODE CLASS="h2black"><A HREF=".+?">(.+?)</A></CODE>|g) {
                push @emails, $1;
            }
            if (scalar @nameservers && scalar @emails) {
                $resp = '';
                foreach my $ns (@nameservers) {
                    $resp .= "nserver:      $ns\n";
                }
                foreach my $email (@emails) {
                    $resp .= "e-mail:       $email\n";
                }
            }
        }

    } elsif ($tld eq 'mu') {

        return 0 unless
        $resp =~ /(<p><b>Domain Name:<\/b><br>.+?)<hr width="75%">/s;
        $resp = $1;
        $ishtml = 1;

    } elsif ($tld eq 'ru' || $tld eq 'su') {

        $resp = _koi2win($resp);
        (undef, $resp) = split('<script>.*?</script>',$resp);
        ($resp) = split('</td></tr></table>', $resp);
        $resp =~ s/&nbsp;/ /gi;
        $resp =~ s/<([^>]|\n)*>//gi;

        return 0 if ($resp=~ m/Доменное имя .*? не зарегистрировано/i);
        $resp = 'ERROR' if $resp =~ m/Error:/i || $resp !~ m/Информация о домене .+? \(по данным WHOIS.RIPN.NET\):/;;
        #TODO: errors
    } elsif ($tld eq 'ip') {

        unless ($resp =~ m|<p ID="whois">(.+?)</p>|s) {
            return 0;
        }

        $resp = $1;
        
        $resp =~ s|<a.+?>||g;
        $resp =~ s|</a>||g;
        $resp =~ s|<br>||g;
        $resp =~ s|&nbsp;| |g;

    } elsif ($tld eq 'in') {

        if ($resp =~ /Domain ID:\w{3,10}-\w{4}\n(.+?)\n\n/s) {
            $resp = $1;
            $resp =~ s/<br>//g;
        } else {
            return 0;
        }

    } elsif ($tld eq 'cn') {

        if ($resp =~ m|<table border=1 cellspacing=0 cellpadding=2>\n\n(.+?)\n</table>|s) {
            $resp = $1;
            $resp =~ s|<a.+?>||isg;
            $resp =~ s|</a>||isg;
            $resp =~ s|<font.+?>||isg;
            $resp =~ s|</font>||isg;
            $resp =~ s|<tr><td class="t_blue">.+?</td><td class="t_blue">||isg;
            $resp =~ s|</td></tr>||isg;
            $resp =~ s|\n\s+|\n|sg;
            $resp =~ s|\n\n|\n|sg;
        } else {
            return 0;
        }

    } elsif ($tld eq 'ws') {

	if ($resp =~ /Whois information for .+?:(.+?)<table>/s) {
	    $resp = $1;
            $resp =~ s|<font.+?>||isg;
            $resp =~ s|</font>||isg;

            $ishtml = 1;
	} else {
	    return 0;
	}

    } elsif ($tld eq 'kz') {
    
	if ($resp =~ /Domain Name\.{10}/s && $resp =~ /<pre>(.+?)<\/pre>/s) {
	    $resp = $1;
	} else {
	    return 0;
	}

    } else {
        return 0;
    }
    # above untached from Net::Whois::Raw
    
    return $resp;    
}

sub _koi2win($) {
    my $val = $_[0];
    $val =~ tr/бвчздецъйклмнопртуфхжигюыэшщяьасБВЧЗДЕЦЪЙКЛМНОПРТУФХЖИГЮЫЭЯЩШЬАСіЈ/А-яЁё/;
    return $val;
}

sub get_from_cache {
    my ($query, $cache_dir, $cache_time) = @_;

    return undef unless $cache_dir;

    mkdir $cache_dir, 0755 unless -d $cache_dir;
    
    my $now = time;
    # clear the cache
    foreach (glob("$cache_dir/*")) {
        my $mtime = (stat($_))[8] or next;
        my $elapsed = $now - $mtime;
        unlink $_ if ($elapsed / 60 > $cache_time);
    }
    
    if (-f "$cache_dir/$query") {
        if (open(CACHE, "$cache_dir/$query")) {
            my $server = <CACHE>;
            chomp $server;
            my $whois = join("", <CACHE>);
            close(CACHE);
            return $whois, $server;
        }
    }
}

sub write_to_cache {
    my $cache_dir = pop;
    my %result = @_;

    return unless $cache_dir && $result{query} && $result{whois};
    mkdir $cache_dir, 0755 unless -d $cache_dir;

    if (open(CACHE, ">$cache_dir/".$result{query})) {
        print CACHE $result{server}."\n";
        print CACHE $result{whois};
        close(CACHE);
    }
}

sub next_local_ip {
    my ($server, $clientname, $rism) = @_;
    clean_bans();
    #clean_rism($rism) if $rism;
    
    my $i = 0;
    while ($i <= @local_ips) {
        $i++;
        my $next_ip = shift @local_ips || 'localhost';
        push @local_ips, $next_ip
            unless $next_ip eq 'localhost';
        if (!$servers_ban{$server} || !$servers_ban{$server}->{$next_ip}) {
            #if ($clientname && $rism
            #        && $rism_all->{$clientname}->{$next_ip}->{$server}->{count} < $rism) {
            #    $rism_all->{$clientname}->{$next_ip}->{$server}->{count}++;
            #    return $next_ip;                
            #} else {
            #    return $next_ip;
            #}
            return $next_ip;
        }
    }
    
    return undef;
}

#sub clean_rism {
#    my ($rism) = @_;
#    # brainfuck!
#    foreach my $clientname (keys %$rism_all)  {
#        foreach my $ip (keys %{$rism_all->{$clientname}} ) {
#            foreach my $server (keys %{$rism_all->{$clientname}->{$ip}} ) {
#                if (
#                        $rism_all->{$clientname}->{$ip}->{$server}
#                        && ($rism_all->{$clientname}->{$ip}->{$server}->{start} + 61 < time)
#                    ) {
#                    $rism_all->{$clientname}->{$ip}->{$server}->{start} = time;
#                    $rism_all->{$clientname}->{$ip}->{$server}->{count} = 0;
#                }
#            }
#        }
#    }
#}

sub clean_bans {
    #my (@my_local_ips) = @local_ips || ('localhost');
    foreach my $server (keys %servers_ban) {
        foreach my $ip (keys %{$servers_ban{$server}}) {
            #print $POE::Component::Client::Whois::Smart::Data::ban_time{$server}."\n";
            delete $servers_ban{$server}->{$ip}
                if time - $servers_ban{$server}->{$ip}
                    >=
                    (
                        $POE::Component::Client::Whois::Smart::Data::ban_time{$server}
                        || $POE::Component::Client::Whois::Smart::Data::default_ban_time
                    )
                ;
        }
        delete $servers_ban{$server} unless %{$servers_ban{$server}};
    }
}

sub unban_time {
    my ($server, $clientname, $rism) = @_;
    my $unban_time;
    
    my (@my_local_ips) = @local_ips || ('localhost');
    
    foreach my $ip (@my_local_ips) {
        my $ip_unban_time
            = (
                $POE::Component::Client::Whois::Smart::Data::ban_time{$server}
                || $POE::Component::Client::Whois::Smart::Data::default_ban_time
              )
            - (time - $servers_ban{$server}->{$ip});
        $ip_unban_time = 0 if $ip_unban_time < 0;
        $unban_time = $ip_unban_time
            if !defined $unban_time || $unban_time > $ip_unban_time; 
    }

    return $unban_time+1;    
}

1;
__END__

=head1 NAME

POE::Component::Client::Whois::Smart - Provides very quick WHOIS queries with smart features.

=head1 DESCRIPTION

POE::Component::Client::Whois::Smart provides a very quick WHOIS queries
with smart features to other POE sessions and components.
The component will attempt to guess the appropriate whois server to connect
to. Supports cacheing, HTTP-queries to some servers, stripping useless information,
using more then one local IP, handling server's bans.

=head1 SYNOPSIS

    use strict; 
    use warnings;
    use POE qw(Component::Client::Whois::Smart);
    
    my @queries = qw(
        google.com
        yandex.ru
        84.45.68.23
        REGRU-REG-RIPN        
    );
    
    POE::Session->create(
	package_states => [
	    'main' => [ qw(_start _response) ],
	],
    );
    
    $poe_kernel->run();
    exit 0;
    
    sub _start {
        POE::Component::Client::Whois::Smart->whois(
            query => \@queries,
            event => '_response',
        );
    }
    
    sub _response {
        my $all_results = $_[ARG0];
        foreach my $result ( @{$all_results} ) {
            my $query = $result->{query} if $result;
            if ($result->{error}) {
                print "Can't resolve WHOIS-info for ".$result->{query}."\n";
            } else {
                print "QUERY: ".$result->{query}."\n";
                print "SERVER: ".$result->{server}."\n";
                print "WHOIS: ".$result->{whois}."\n\n";
            };
        }                            
    }

=head1 Constructor

=over

=item whois()

Creates a POE::Component::Client::Whois session. Takes two mandatory arguments and a number of optional:

=back

=over 2

=item query

query is an arrayref of domains, IPs or registaras to send to
whois server. Required.

=item event

The event name to call on success/failure. Required.

=item session

A session or alias to send the above 'event' to, defaults to calling session. Optional.

=item server

Specify server to connect. Defaults try to be determined by the component. Optional.

=item referral

Optional.

0 - make just one query, do not follow if redirections can be done;

1 - follow redirections if possible, return last response from server; # default

2 - follow redirections if possible, return all responses;


Exapmle:
   
    #...
    POE::Component::Client::Whois->whois(
        query    => [ 'google.com', 'godaddy.com' ],
        event    => '_response',
        referral => 2,
    );
    #...
    sub _response {
        my $all_results = $_[ARG0];
        
        foreach my $result ( @{$all_results} ) {
            my $query = $result->{query} if $result;
            if ($result->{error}) {
                print "Can't resolve WHOIS-info for ".$result->{query}."\n";
            } else {
                print "Query for: ".$result->{query}."\n";
                # process all subqueries
                my $count = scalar @{$result->{subqueries}};
                print "There were $count subqueries:\n";
                foreach my $subquery (@{$result->{subqueries}}) {
                    print "\tTo server ".$subquery->{server}."\n";
                    # print "\tQuery: ".$subquery->{query}."\n";
                    # print "\tResponse:\n".$subquery->{whois}."\n";
                }
            }
        }                            
    }    
    #...

=item omit_msg

1 - attempt to strip several known copyright messages and disclaimers.

2 - will try some additional stripping rules if some are known for the spcific server.

Default is to give the whole response.

=item use_cnames

Use whois-servers.net to get the whois server name when possible.
Default is to use the hardcoded defaults.

=item timeout

Cancel the request if connection is not made within a specific number of seconds.
Default 30 sec.

=item local_ips

List of local IP addresses to use for WHOIS queries.

=item cache_dir

Whois information will be cached in this directory. Default is no cache.

=item cache_time

Number of minutes to save cache. 1 minute by default.

=item exceed_wait

If exceed_wait true, will wait for for 1 minute and requery server in case if your IP banned for excessive querying.
By default return 'Connection rate exceeded' in $result->{error};

=head1 OUTPUT

ARG0 will be an array of hashrefs, which contains replies.
See example above.

=head1 AUTHOR

Sergey Kotenko <graykot@gmail.com>

This module is based on the Net::Whois::Raw L<http://search.cpan.org/perldoc?Net::Whois::Raw>
and POE::Component::Client::Whois L<http://search.cpan.org/perldoc?POE::Component::Client::Whois>

=head1 SEE ALSO

RFC 812 L<http://www.faqs.org/rfcs/rfc812.html>.
