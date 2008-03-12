package POE::Component::Client::Whois::Smart;

use strict;
use warnings;
use Socket;
use POE qw(Filter::Line Wheel::ReadWrite Wheel::SocketFactory Component::Client::HTTP);
use HTTP::Request;
use Net::Whois::Raw::Common;
use Net::Whois::Raw::Data;
use Storable;
#use Data::Dumper;

our $VERSION = '0.11';
our $DEBUG;
our @local_ips = ();
our %servers_ban = ();
our %POSTPROCESS;
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
        = defined $args{omit_msg} ? delete $args{omit_msg} : 2;
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
    if ($response->{error}) {
        $error = $response->{error};
    } elsif($response->{from_cache}) {
        $whois = $response->{whois};
        $heap->{result}->{$response->{original_query}} = delete $response->{cache};
    } elsif ($response->{host} eq "www_whois") {
        $whois = $response->{whois};
        $error = $response->{error};
    } else {
        $whois = defined $response->{reply} ? join "\n", @{$response->{reply}} : "";
        delete $response->{reply};
        ($whois, $error) = Net::Whois::Raw::Common::process_whois(
            $response->{original_query},
            $response->{host},
            $whois,
            2, $heap->{params}->{omit_msg}, 2,
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
    
    if (!$response->{from_cache} && ( !$error || !$heap->{result}->{$response->{original_query}} ) ) {
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
        ) if $result{whois} && $response->{host} ne "www_whois";
        
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
            my $num = $heap->{params}->{referral} == 0 ? 0 : -1;
            my %res = (
                query  => $query,
                whois  => $heap->{result}->{$query}->[$num]->{whois},
                server => $heap->{result}->{$query}->[$num]->{server},
                error  => $heap->{result}->{$query}->[$num]->{error},                
            );
            
            Net::Whois::Raw::Common::write_to_cache(
                $query,
                $heap->{result}->{$query},
                $heap->{params}->{cache_dir}
            ) if $heap->{params}->{cache_dir} && !$res{from_cache};
            
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
        my $whois_server = Net::Whois::Raw::Common::get_server($args{query}, $args{params}->{use_cnames});
        unless ( $whois_server ) {
            warn "Could not determine whois server from query string, defaulting to internic \n";
            $whois_server = 'whois.internic.net';
        }
        $args{host} = $whois_server;
    }

    $args{query_real} = Net::Whois::Raw::Common::get_real_whois_query($args{query}, $args{host})
        unless ($args{host} eq "www_whois");

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
    
    if ($self->{request}->{cache_dir}) {
        my $result = Net::Whois::Raw::Common::get_from_cache(
            $self->{request}->{query},
            $self->{request}->{cache_dir},
            $self->{request}->{cache_time},            
        );
        if ($result) {            
            my $request = delete $self->{request};
            my $session = delete $request->{manager_id};
            
            #$request->{whois}      = $whois;
            #$request->{host}       = $server;
            
            my $res;
            foreach (@{$result}) {
                $_->{server} = delete $_->{srv};
                $_->{whois} = delete $_->{text};
                push @{$res}, $_;
            }
            
            $request->{cache}       = $res;
            $request->{from_cache} = 1;
            $kernel->post( $session => $request->{event} => $request );
            return undef;
        }
    }
    
    if ($self->{request}->{host} eq "www_whois") {
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
        warn "All IPs banned for server ".$self->{request}->{host}.
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
        Timeout => $self->{request}->{timeout},
    );
    
    my ($url, %form) = Net::Whois::Raw::Common::get_http_query_url($self->{request}->{query});
    my ($name, $tld) = Net::Whois::Raw::Common::split_domain($self->{request}->{query});
    
    $self->{request}->{tld} = $tld;
    my $referer = delete $form{referer} if %form && $form{referer};
    my $method = scalar(keys %form) ? 'POST' : 'GET';
    
    my $header = HTTP::Headers->new;
    $header->header('Referer' => $referer) if $referer;
    my $req = new HTTP::Request $method, $url, $header;

    if ($method eq 'POST') {
        my $curl = url("http:");
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
        = Net::Whois::Raw::Common::parse_www_content($content, $self->{request}->{tld});
    
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

    $kernel->delay_add( '_time_out' => $self->{request}->{timeout});
    $self->{'socket'}->put( $self->{request}->{query_real} );
    
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
    warn "Timeout!";
    
    my $request = delete $self->{request};
    my $session = delete $request->{manager_id};
    $request->{error} = "Timeout";
    $kernel->post( $session => $request->{event} => $request );
    
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
	    $new_server = $Net::Whois::Raw::Data::ip_whois_servers{ $1 };
            #last;
    	} elsif ((/OrgID:\s+(\w+)/ || /descr:\s+(\w+)/) && Net::Whois::Raw::Common::is_ipaddr($query)) {
	    my $value = $1;	
	    if($value =~ /^(?:RIPE|APNIC|KRNIC|LACNIC)$/) {
		$new_server = $Net::Whois::Raw::Data::ip_whois_servers{$value};
		last;
	    }
    	} elsif (/^\s+Maintainer:\s+RIPE\b/ && Net::Whois::Raw::Common::is_ipaddr($query)) {
            $new_server = $Net::Whois::Raw::Data::servers{RIPE};
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
            #print $Net::Whois::Raw::Data::ban_time{$server}."\n";
            delete $servers_ban{$server}->{$ip}
                if time - $servers_ban{$server}->{$ip}
                    >=
                    (
                        $Net::Whois::Raw::Data::ban_time{$server}
                        || $Net::Whois::Raw::Data::default_ban_time
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
                $Net::Whois::Raw::Data::ban_time{$server}
                || $Net::Whois::Raw::Data::default_ban_time
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

0 - give the whole response.

1 - attempt to strip several known copyright messages and disclaimers.

2 - will try some additional stripping rules if some are known for the spcific server.

Default is 2;

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
