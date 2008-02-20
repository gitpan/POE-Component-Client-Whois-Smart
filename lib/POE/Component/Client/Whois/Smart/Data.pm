package POE::Component::Client::Whois::Smart::Data;

use strict;
use warnings;
use Net::Netmask;

sub new {
  my $self = bless { }, shift;
  $self->{data} = {
                             '210.120.0.0/14' => 'whois.nic.or.kr',
                             '145.224.0.0/12' => 'whois.ripe.net',
                             '62.0.0.0/8' => 'whois.ripe.net',
                             '202.30.0.0/15' => 'whois.nic.or.kr',
                             '200.18.0.0/15' => 'whois.nic.br',
                             '210.224.0.0/12' => 'whois.nic.ad.jp',
                             '202.23.0.0/16' => 'whois.nic.ad.jp',
                             '192.72.0.0/16' => 'whois.seed.net.tw',
                             '160.48.0.0/12' => 'whois.ripe.net',
                             '211.112.0.0/13' => 'whois.nic.or.kr',
                             '203.35.0.0/16' => 'whois.telstra.net',
                             '164.32.0.0/13' => 'whois.ripe.net',
                             '192.164.0.0/14' => 'whois.ripe.net',
                             '211.32.0.0/11' => 'whois.nic.or.kr',
                             '139.20.0.0/14' => 'whois.ripe.net',
                             '202.15.0.0/16' => 'whois.nic.ad.jp',
                             '171.16.0.0/12' => 'whois.ripe.net',
                             '145.252.0.0/15' => 'whois.ripe.net',
                             '211.0.0.0/12' => 'whois.nic.ad.jp',
                             '211.104.0.0/13' => 'whois.nic.or.kr',
                             '151.100.0.0/16' => 'whois.ripe.net',
                             '203.36.0.0/14' => 'whois.telstra.net',
                             '145.240.0.0/13' => 'whois.ripe.net',
                             '149.202.0.0/15' => 'whois.ripe.net',
                             '210.61.0.0/16' => 'whois.twnic.net',
                             '163.160.0.0/12' => 'whois.ripe.net',
                             '210.71.128.0/16' => 'whois.twnic.net',
                             '24.192.0.0/14' => 'whois.apnic.net',
                             '210.204.0.0/14' => 'whois.nic.or.kr',
                             '0.0.0.0/2' => 'whois.arin.net',
                             '61.0.0.0/8' => 'whois.apnic.net',
                             '210.96.0.0/13' => 'whois.nic.or.kr',
                             '203.74.0.0/15' => 'whois.twnic.net',
                             '216.0.0.0/8' => 'whois.arin.net',
                             '210.128.0.0/11' => 'whois.nic.ad.jp',
                             '164.128.0.0/12' => 'whois.ripe.net',
                             '210.112.0.0/13' => 'whois.nic.or.kr',
                             '210.65.0.0/16' => 'whois.twnic.net',
                             '149.208.0.0/12' => 'whois.ripe.net',
                             '202.224.0.0/11' => 'whois.nic.ad.jp',
                             '210.92.0.0/14' => 'whois.nic.or.kr',
                             '218.216.0.0/13' => 'whois.apnic.net',
                             '210.180.0.0/14' => 'whois.nic.or.kr',
                             '203.66.0.0/16' => 'whois.twnic.net',
                             '220.0.0.0/8' => 'whois.apnic.net',
                             '61.192.0.0/12' => 'whois.nic.ad.jp',
                             '139.24.0.0/14' => 'whois.ripe.net',
                             '210.241.224.0/19' => 'whois.twnic.net',
                             '202.16.0.0/14' => 'whois.nic.ad.jp',
                             '141.80.0.0/14' => 'whois.ripe.net',
                             '149.224.0.0/12' => 'whois.ripe.net',
                             '133.0.0.0/8' => 'whois.nic.ad.jp',
                             '211.128.0.0/13' => 'whois.nic.ad.jp',
                             '202.24.0.0/15' => 'whois.nic.ad.jp',
                             '203.178.0.0/15' => 'whois.nic.ad.jp',
                             '203.136.0.0/14' => 'whois.nic.ad.jp',
                             '141.0.0.0/10' => 'whois.ripe.net',
                             '211.20.0.0/15' => 'whois.twnic.net',
                             '203.58.128.0/17' => 'whois.telstra.net',
                             '149.206.0.0/15' => 'whois.ripe.net',
                             '203.40.0.0/13' => 'whois.telstra.net',
                             '151.64.0.0/11' => 'whois.ripe.net',
                             '145.254.0.0/16' => 'whois.ripe.net',
                             '203.48.0.0/14' => 'whois.telstra.net',
                             '218.0.0.0/7' => 'whois.apnic.net',
                             '202.11.0.0/16' => 'whois.nic.ad.jp',
                             '210.0.0.0/7' => 'whois.apnic.net',
                             '203.58.32.0/19' => 'whois.telstra.net',
                             '210.62.252.0/22' => 'whois.twnic.net',
                             '149.204.0.0/16' => 'whois.ripe.net',
                             '61.208.0.0/13' => 'whois.nic.ad.jp',
                             '203.232.0.0/13' => 'whois.nic.or.kr',
                             '141.64.0.0/12' => 'whois.ripe.net',
                             '210.188.0.0/14' => 'whois.nic.ad.jp',
                             '196.0.0.0/6' => 'whois.arin.net',
                             '61.112.0.0/12' => 'whois.nic.ad.jp',
                             '200.20.0.0/16' => 'whois.nic.br',
                             '200.17.0.0/16' => 'whois.nic.br',
                             '202.13.0.0/16' => 'whois.nic.ad.jp',
                             '204.0.0.0/6' => 'whois.arin.net',
                             '211.120.0.0/13' => 'whois.nic.ad.jp',
                             '150.254.0.0/16' => 'whois.ripe.net',
                             '211.168.0.0/13' => 'whois.nic.or.kr',
                             '192.0.0.0/8' => 'whois.arin.net',
                             '202.208.0.0/12' => 'whois.nic.ad.jp',
                             '146.48.0.0/16' => 'whois.ripe.net',
                             '160.220.0.0/16' => 'whois.ripe.net',
                             '194.0.0.0/7' => 'whois.ripe.net',
                             '202.39.128.0/17' => 'whois.twnic.net',
                             '198.17.117.0/24' => 'whois.ripe.net',
                             '210.196.0.0/14' => 'whois.nic.ad.jp',
                             '163.156.0.0/14' => 'whois.ripe.net',
                             '203.27.128.0/18' => 'whois.telstra.net',
                             '151.0.0.0/10' => 'whois.ripe.net',
                             '164.0.0.0/11' => 'whois.ripe.net',
                             '211.176.0.0/12' => 'whois.nic.or.kr',
                             '200.0.0.0/7' => 'whois.arin.net',
                             '211.192.0.0/10' => 'whois.nic.or.kr',
                             '200.128.0.0/9' => 'whois.nic.br',
                             '211.22.0.0/16' => 'whois.twnic.net',
                             '208.0.0.0/7' => 'whois.arin.net',
                             '149.248.0.0/14' => 'whois.ripe.net',
                             '139.28.0.0/15' => 'whois.ripe.net',
                             '80.0.0.0/7' => 'whois.ripe.net',
                             '218.224.0.0/13' => 'whois.apnic.net',
                             '203.180.0.0/14' => 'whois.nic.ad.jp',
                             '210.90.0.0/15' => 'whois.nic.or.kr',
                             '171.32.0.0/15' => 'whois.ripe.net',
                             '203.52.0.0/15' => 'whois.telstra.net',
                             '193.0.0.0/8' => 'whois.ripe.net',
                             '212.0.0.0/7' => 'whois.ripe.net',
                             '214.0.0.0/7' => 'whois.arin.net',
                             '202.26.0.0/16' => 'whois.nic.ad.jp',
                             '217.0.0.0/8' => 'whois.ripe.net',
                             '211.16.0.0/14' => 'whois.nic.ad.jp',
                             '149.240.0.0/13' => 'whois.ripe.net',
                             '203.69.0.0/16' => 'whois.twnic.net',
                             '210.248.0.0/13' => 'whois.nic.ad.jp',
                             '210.160.0.0/12' => 'whois.nic.ad.jp',
                             '24.132.0.0/14' => 'whois.ripe.net',
                             '160.44.0.0/14' => 'whois.ripe.net',
                             '211.75.0.0/16' => 'whois.twnic.net',
                             '145.248.0.0/14' => 'whois.ripe.net',
                             '203.140.0.0/15' => 'whois.nic.ad.jp',
                             '218.47.0.0/13' => 'whois.nic.or.kr',
                             '218.40.0.0/13' => 'whois.nic.ad.jp',
                             '210.59.128.0/17' => 'whois.twnic.net',
                             '210.241.0.0/15' => 'whois.twnic.net',
                             '203.0.0.0/10' => 'whois.apnic.net',
                             '192.71.0.0/16' => 'whois.ripe.net',
                             '211.72.0.0/16' => 'whois.twnic.net',
                             '210.216.0.0/13' => 'whois.nic.or.kr',
                             '203.54.0.0/16' => 'whois.telstra.net',
                             '202.0.0.0/7' => 'whois.apnic.net',
                             '210.240.0.0/16' => 'whois.twnic.net',
                             '192.106.0.0/16' => 'whois.ripe.net',
                             '203.58.64.0/19' => 'whois.telstra.net',
                             '141.84.0.0/15' => 'whois.ripe.net',
                             '151.96.0.0/14' => 'whois.ripe.net',
                             '202.32.0.0/14' => 'whois.nic.ad.jp',
                             '192.162.0.0/16' => 'whois.ripe.net',
                             '169.208.0.0/12' => 'whois.apnic.net',
                             '202.48.0.0/16' => 'whois.nic.ad.jp',
                             '210.178.0.0/15' => 'whois.nic.or.kr',
                             '210.242.0.0/15' => 'whois.twnic.net',
                             '164.40.0.0/16' => 'whois.ripe.net',
                             '210.104.0.0/13' => 'whois.nic.or.kr',
                             '160.216.0.0/14' => 'whois.ripe.net',
			     '58.0.0.0/8' => 'whois.apnic.net',
                           };
  return $self;
}

sub get_ip_server {
  my $self = shift;
  my $ip = shift || return undef;

  foreach my $range ( keys %{ $self->{data} } ) {
	if ( $range eq '0.0.0.0/2' ) {
		foreach my $cls_a ( 1 .. 126 ) {
		  my $block2 = Net::Netmask->new( "$cls_a.0.0.0/8" );
		  if ( $block2->match( $ip ) ) {
			return ( $self->{data}->{ $range }, $range );
		  }
		}
	}
	my $block = Net::Netmask->new( $range );
	if ( $block->match( $ip ) ) {
		return ( $self->{data}->{ $range }, $range );
	}
  }
  return undef;
}

our @www_whois = qw(
    IN
    SPB.RU
    MSK.RU
);

our %servers = qw(
    NS     whois.nsiregistry.net
    RIPE   whois.ripe.net
    IP     whois.arin.net

    AERO   whois.aero
    ARPA   whois.arin.net
    BIZ    whois.biz
    CAT    whois.cat
    COM    whois.crsnic.net
    COOP   whois.nic.coop
    EDU    whois.educause.edu
    GOV    whois.dotgov.gov
    INFO   whois.afilias.net
    INT    whois.iana.org
    MIL    whois.nic.mil
    MOBI   whois.dotmobiregistry.net
    MUSEUM whois.museum
    NAME   whois.nic.name
    NET    whois.crsnic.net
    ORG    whois.pir.org
    PRO    whois.registrypro.pro

    AC  whois.nic.ac
    AG  whois.nic.ag
    AM  whois.amnic.net
    AT  whois.nic.at
    AU  whois.aunic.net
    BE  whois.dns.be
    BG  whois.register.bg
    BJ  whois.nic.bj
    BR  whois.registro.br
    CA  whois.cira.ca
    CH  whois.nic.ch
    CI  whois.nic.cI
    CL  Whois.nic.cl
    CN  whois.cnnic.net.cn
    CX  whois.nic.cx
    CZ  whois.nic.cz
    DE  whois.denic.de
    DK  whois.dk-hostmaster.dk
    EE  whois.eenet.ee
    EU  whois.eu
    FI  whois.ficora.fi
    FR  whois.nic.fr
    GG  whois.channelisles.net
    GI  whois2.afilias-grs.net
    GS  whois.nic.gs
    HK  whois.hkirc.hk
    HN  whois2.afilias-grs.net
    IE  whois.domainregistry.ie
    IL  whois.isoc.org.il
    IN  whois.inregistry.net
    IO  whois.nic.io
    IS  whois.isnic.is
    IT  whois.nic.it
    JE  whois.channelisles.net
    JP  whois.jprs.jp
    KE  whois.kenic.or.ke
    KR  whois.nic.or.kr
    KZ  whois.nic.kz
    LA  whois2.afilias-grs.net
    LI  whois.nic.li
    LT  whois.domreg.lt
    LU  whois.dns.lu
    LV  whois.nic.lv
    MG  whois.nic.mg
    MN  whois.nic.mn
    MS  whois.adamsnames.tc
    MX  whois.nic.mx
    MY  whois.mynic.net.my
    NA  whois.na-nic.com.na
    NL  whois.domain-registry.nl
    NO  whois.norid.no
    NU  whois.nic.nu
    NZ  whois.srs.net.nz
    PL  whois.dns.pl
    PM  whois.nic.pm
    PR  whois.uprr.pr
    RE  whois.nic.re
    RO  whois.rotld.ro
    RU  whois.ripn.net
    SB  whois.nic.net.sb
    SC  whois2.afilias-grs.net
    SE  whois.iis.se
    SG  whois.nic.net.sg
    SH  whois.nic.sh
    SI  whois.arnes.si
    ST  whois.nic.st
    SU  whois.ripn.net
    TC  whois.adamsnames.tc
    TF  whois.nic.tf
    TK  whois.dot.tk
    TL  whois.nic.tl
    TM  whois.nic.tm
    TR  whois.nic.tr
    TW  whois.twnic.net.tw
    UA  whois.net.ua
    UK  whois.nic.uk
    US  whois.nic.us
    UZ  whois.cctld.uz
    VC  whois2.afilias-grs.net
    VE  whois.nic.ve
    VG  whois.adamsnames.tc
    WF  whois.nic.wf
    YT  whois.nic.yt

    CC  whois.nic.cc
    DM  whois.nic.cx
    DO  ns.nic.do
    HU  whois.nic.hu
    MU  whois.nic.cx
    NF  whois.nic.cx
    PT  whois.dns.pt
    TO  whois.tonic.to
    TP  whois.nic.cx
    WS  whois.worldsite.ws

    AC.UK	whois.ja.net
    GOV.UK	whois.ja.net

    XN---P1AG	ru.whois.i-dns.net
    XN---P1AG	ru.whois.i-dns.net
    XN---J1AEF	whois.i-dns.net
    XN---E1APQ	whois.i-dns.net
    XN---C1AVG	whois.i-dns.net

    COM.RU	whois.ripn.net
    NET.RU	whois.ripn.net
    ORG.RU	whois.ripn.net
    PP.RU	whois.ripn.net
    SPB.RU	whois.relcom.ru
    MSK.RU	whois.relcom.ru
    RU.NET	whois.relcom.ru
    YES.RU	whois.regtime.net

    EU.COM      whois.centralnic.com
    GB.COM      whois.centralnic.com
    KR.COM	whois.centralnic.com
    US.COM	whois.centralnic.com
    QC.COM	whois.centralnic.com
    DE.COM	whois.centralnic.com
    NO.COM	whois.centralnic.com
    HU.COM	whois.centralnic.com
    JPN.COM	whois.centralnic.com
    UY.COM	whois.centralnic.com
    ZA.COM	whois.centralnic.com
    BR.COM	whois.centralnic.com
    CN.COM	whois.centralnic.com
    SA.COM	whois.centralnic.com
    SE.COM	whois.centralnic.com
    UK.COM      whois.centralnic.com
    RU.COM	whois.centralnic.com

    GB.NET      whois.centralnic.com
    UK.NET      whois.centralnic.com
    SE.NET	whois.centralnic.com

    AE.ORG	whois.centralnic.com
);

# These serve only several subdomains
#         ZA  apies.frd.ac.za

our %ip_whois_servers = qw(
    AFRINIC	whois.afrinic.net
    APNIC	whois.apnic.net
    ARIN	whois.arin.net
    LACNIC	whois.lacnic.net
    RIPE	whois.ripe.net

    JPNIC	whois.nic.ad.jp
    KRNIC	whois.krnic.net
);


our %notfound = (
    'whois.arin.net' => '^No match for',
    'whois.ripe.net' => 'No entries found',

    'whois.biz' => '^Not found:',
    'whois.nic.coop' => 'No Objects Found',
    'whois.afilias.net' => '^NOT FOUND',
    'whois.nic.mil' => '^No match for',
    'whois.museum' => '^No information for',
    'whois.nic.kz' => 'Nothing found for this query',
    'whois.nic.at' => 'nothing found',
    'whois.aunic.net' => 'No Data Found',
    'whois.dns.be' => '^Status:      FREE',
    'whois.registro.br' => 'No match for',
    'whois.cira.ca' => 'Status:\\s*UNAV',
    'whois.nic.ch' => '^We do not have an entry in our database matching your',
    'whois.nic.cl' => 'Invalid domain name',
    'whois.nic.cx' => 'Status: Not Registered',
    'whois.nic.cz' => 'No data found',
    'whois.denic.de' => 'No entries found',
    'whois.eu' => '^Status:      FREE',
    'whois.nic.fr' => 'No entries found',
    'whois.nic.gs' => 'Status: Not Registered',
    'whois.hkirc.hk' => '^No Match for',
    'whois.nic.hu' => 'No match',
    'whois.domainregistry.ie' => 'There was no match',
    'whois.isoc.org.il' => 'No data was found',
    'whois.inregistry.net' => '^No matches',
    'whois.isnic.is' => 'No entries found',
    'whois.nic.it' => 'Status:             AVAILABLE',
    'whois.jprs.jp' => 'No match',
    'whois.nic.or.kr' => 'Above domain name is not registered',
    'whois2.afilias-grs.net' => '^NO MATCH for',
    'whois.domreg.lt' => 'No matches found',
    'whois.dns.lu' => 'No such domain',
    'whois.nic.mx' => '^Nombre del Dominio:',
    'whois.mynic.net.my' => 'does not Exist in database',
    'whois.na-nic.com.na' => 'No records matching',
    'whois.domain-registry.nl' => 'is free',
    'whois.norid.no' => 'no matches',
    'whois.srs.net.nz' => 'query_status: 220 Available',
    'whois.dns.pl' => 'No information about domain',
    'whois.uprr.pr' => 'No records matching',
    'whois.dns.pt' => 'no match',
    'whois.rotld.ro' => 'No entries found',
    'whois.ripn.net' => 'No entries found',
    'whois.iis.se' => 'No data found',
    'whois.nic.net.sg' => 'NO entry found',
    'whois.nic.sh' => 'Not available',
    'whois.arnes.si' => 'No entries found',
    'whois.nic.st' => '^No entries found',
    'whois.adamsnames.tc' => 'is not a domain controlled by',
    'whois.nic.tl' => 'Status: Not Registered',
    'whois.twnic.net.tw' => '^No Found',
    'whois.net.ua' => 'No entries found for domain',
    'whois.nic.uk' => '^\\s*No match for',
    'whois.nic.ve' => 'No match for',

    'whois.nic.cc' => '^No match for',
    'whois.tonic.to' => 'No match for',
    'whois.worldsite.ws' => 'No match for',

    'whois.networksolutions.com' => '(?i)no match',
    'whois.melbourneit.com' => '^Invalid/Unsupported whois name check',

    'apies.frd.ac.za' => 'No information is available',
    'whois.worldnames.net' => 'NO MATCH for domain',
    'whois.nic.tj' => '^No match for',
    'whois.gdns.net' => '^Domain Not Found',
    'whois.thnic.net' => 'No entries found',
);

our %strip = (
    'whois.crsnic.net' => [
	'^TERMS OF USE:',
	'^database through',
	'^automated except',
	'^modify existing',
	'^Services\' \(\"VeriSign\"\)',
	'^information purposes only',
	'^about or related to a',
	'^guarantee its accuracy\.',
	'^by the following terms',
	'^for lawful purposes and',
	'^to: (1) allow, enable,',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\)',
	'^that apply to VeriSign',
	'^repackaging, dissemination',
	'^prohibited without the',
	'^use electronic processes',
	'^query the Whois database',
	'^domain names or modify',
	'^to restrict your access',
	'^operational stability\.',
	'^Whois database for',
	'^reserves the right',

	'^NOTICE AND TERMS OF USE:',
	'^Data in Network Solutions',
	'^purposes only, and to assist',
	'^to a domain name registration',
	'^By submitting a WHOIS query,',
	'^You agree that you may use',
	'^circumstances will you use',
	'^the transmission of mass',
	'^via e-mail, telephone, or',
	'^electronic processes that',
	'^compilation, repackaging,',
	'^high-volume, automated,',
	'^database. Network Solutions',
	'^database in its sole discretion,',
	'^querying of the WHOIS database',
	'^Network Solutions reserves the',

	'^NOTICE: The expiration date',
	'^registrar\'s sponsorship of',
	'^currently set to expire\.',
	'^date of the domain name',
	'^registrar.  Users may',
	'^view the registrar\'s',
	'^to: \(1\) allow, enable,',
	'^The Registry database',
	'^Registrars\.',
	'^Domain not found locally,',
	'^Local WHOIS DB must be out',

	'^Whois Server Version',
	'^Domain names in the .com',
	'^with many different',
	'^for detailed information\.',

	'^>>> Last update of whois database',
	'^$',
    ],

    'whois.arin.net' => [
	'^The ARIN Registration Services Host contains',
	'^Network Information:.*Networks',
	'^Please use the whois server at',
	'^Information and .* for .* Information.',
    ],
    'whois.ripe.net' => [
	'^%',
    ],

    'whois.nic.coop' => [
	'^%',
	'^ The .COOP Registration',
	'^ Please use the',
    ],
    'whois.nic.mil' => [
	'^To single out one record',
	'^handle, shown in parenthesis',
	'^Please be advised that this whois',
	'^All INTERNET Domain, IP Network Number,',
	'^the Internet Registry, RS.INTERNIC.NET.',
    ],

    'whois.nic.at' => [
	'^%',
    ],
    'whois.aunic.net' => [
	'^%',
    ],
    'whois.dns.be' => [
	'^%-',
    ],
    'whois.registro.br' => [
	'^%',
    ],
    'whois.nic.ch' => [
	'^whois: This information is subject',
	'^See http',
    ],
    'whois.nic.cl' => [
	'^cl.cl:',
	'^Más información: http://www.nic.cl/',
    ],
    'whois.nic.cx' => [
	'^ Registrar: Christmas Island',
	'^ Whois Server: whois.nic.cx',
    ],
    'whois.nic.cz' => [
	'^%',
    ],
    'whois.denic.de' => [
	'^%',
    ],
    'whois.eu' => [
	'^%-',
    ],
    'whois.nic.fr' => [
	'^Tous droits reserves par copyright.',
	'^Voir http://www.nic.fr',
	'^Rights restricted by copyright.',
	'^See http://www.nic.fr/outils',
    ],
    'whois.hkirc.hk' => [
	'^Whois server',
	'^Domain names in the',
	'^and .* can now be registered',
	'^Go to http://www.hkdnr.net.hk',
	'^---------',
	'^The Registry contains ONLY',
	'^.* and .*\\.HK domains.',
    ],
    'whois.nic.hu' => [
	'^%',
    ],
    'whois.domainregistry.ie' => [
	'^%',
    ],
    'whois.isoc.org.il' => [
	'^%',
    ],
    'whois.isnic.is' => [
	'^%',
    ],
    'whois.jprs.jp' => [
	'^\[\s+',
    ],
    'whois.nic.or.kr' => [
	'^Korea Internet Information Service',
	'^20\\d\\d³â 7¿ù 2ÀÏºÎÅÍ´Â °³¼±µÈ Whois',
	'^.com, .net, .org',
    ],
    'whois2.afilias-grs.net' => [
	'^   WHOIS server',
	'^   The Data in the',
	'for information purposes,',
	'^   and to assist persons in obtaining',
	'^   domain name registration record. Sterling Holdings, Limited,',
	'^   does not guarantee its accuracy.',
	'^   you will use this Data only for lawful',
	'^   circumstances will you use this Data',
	'^   \\(1\\) allow, enable, or otherwise s',
	'^   unsolicited, commercial advertising',
	'^   \\(spam\\); or',
	'^   that apply to Sterling Holdings',
	'^   Sterling Holdings .* reserves the right to modify',
	'^   terms at any time. By submitting this',
	'^   policy.',
    ],
    'whois.domreg.lt' => [
	'^%',
    ],
    'whois.dns.lu' => [
	'^%',
    ],
    'whois.nic.mx' => [
	'^------------------',
	'^La información que ha',
	'^relacionados con la',
	'^DNS administrado por el NIC-México.',
	'^Queda absolutamente prohibido',
	'^envío de e-mail no solicitado',
	'^productos y servicios',
	'^del NIC-México.',
	'^La base de datos generada',
	'^protegida por las leyes de',
	'^internacionales sobre la materia.',
    ],
    'whois.domain-registry.nl' => [
	'Rights restricted by copyright',
	'http://www.domain-registry.nl',
    ],
    'whois.norid.no' => [
	'^%',
    ],
    'whois.srs.net.nz' => [
	'^%',
    ],
    'whois.dns.pl' => [
	'^%',
    ],
    'whois.rotld.ro' => [
	'^%',
    ],
    'whois.ripn.net' => [
	'^%',
	'Last updated on ',
    ],
    'whois.iis.se' => [
	'^#',
    ],
    'whois.nic.net.sg' => [
	'^\\*',
    ],
    'whois.nic.sh' => [
	'^NIC Whois Server',
    ],
    'whois.arnes.si' => [
	'^\\*',
    ],
    'whois.nic.st' => [
	'^The data in the .* database is provided',
	'^The .* Registry does not guarantee',
	'^The data in the .* database is protected',
	'^By submitting a .* query, you agree that you will',
	'^The Domain Council of .* reserves the right',
    ],
    'whois.tonic.to' => [
	'^Tonic whoisd',
    ],
    'whois.twnic.net.tw' => [
	'^Registrar:',
	'^URL: http://rs.twnic.net.tw',
    ],
    'whois.net.ua' => [
	'^%',
    ],
    'whois.nic.uk' => [
	'^The .* Registration Host contains information',
	'^registrations in the .*co.uk',
	'and .*\\.uk second-level domains.',
    ],

    'whois.nic.cc' => [
	'^This information is',
	'^The Data in eNIC',
	'^Corporation for information',
	'^in obtaining information',
	'^registration record',
	'^accuracy.  By submitting',
	'^will use this Data only',
	'^no circumstances will',
	'^or otherwise support',
	'^commercial advertising',
	'^or \\(2\\) enable high volume',
	'^apply to eNIC Corporation',
	'^reserves the right to',
	'^submitting this query,',
    ],
    'whois.worldsite.ws' => [
	'^Welcome to the .* Whois Server',
	'^Use of this service for any',
	'^than determining the',
	'^in the .* to be registered',
	'^prohibited.',
    ],

    'whois.networksolutions.com' => [
	'^The Data in',
	'^Solutions for information',
	'^information about or',
	'^Network Solutions does not guarantee',
	'^WHOIS query, you agree that',
	'^purposes and that, under no circumstances',
	'^\\(1\\) allow, enable, or',
	'^unsolicited, commercial advertising',
	'^\\(spam\\); or',
	'^that apply to Network',
	'^reserves the right',
	'^this query, you',
	'^Get a FREE domain name registration, transfer,',
	'^- or just \$8.95 with monthly packages.',
	'^http://www.networksolutions.com',
	'^Visit AboutUs.org for more information',
	'^<a href="http://www.aboutus.org/GREENSTYLE.COM">',
    ],
    'whois.directnic.com' => [
	'^By submitting a WHOIS query',
	'^lawful purposes\.  You also agree',
	'^this data to:',
	'^email, telephone,',
	'^or solicitations to',
	'^customers; or to \(b\) enable',
	'^that send queries or data to',
	'^ICANN-Accredited registrar\.',
	'^The compilation, repackaging,',
	'^data is expressly prohibited',
	'^directNIC.com\.',
	'^directNIC.com reserves the right',
	'^database in its sole discretion,',
	'^excessive querying of the database',
	'^this policy\.',
	'^directNIC reserves the right to',
	'^NOTE: THE WHOIS DATABASE IS A',
	'^LACK OF A DOMAIN RECORD DOES',
	'^Intercosmos Media Group, Inc',
	'^Registrar WHOIS database for',
	'^may only be used to assist in',
	'^registration record\.',
	'^directNIC makes this information',
	'^its accuracy\.',
    ],
    'whois.alldomains.com' => [
	'^MarkMonitor.com - ',
	'^------------------',
	'^For Global Domain ',
	'^and Enterprise DNS,',
	'^------------------',
	'^The Data in MarkMon',
	'^for information pur',
	'^about or related to',
	'^does not guarantee ',
	'^that you will use t',
	'^circumstances will ',
	'^support the transmi',
	'^solicitations via e',
	'^electronic processe',
	'^MarkMonitor.com res',
	'^By submitting this ',
    ],

    'whois.gdns.net' => [
	'^\\w+ Whois Server',
	'^Access to .* WHOIS information is provided to',
	'^determining the contents of a domain name',
	'^registrar database.  The data in',
	'^informational purposes only, and',
	'^Compilation, repackaging, dissemination,',
	'^in its entirety, or a substantial portion',
	'prior written permission.  By',
	'^by this policy.  All rights reserved.',
    ],
    'whois.worldnames.net' => [
	'^----------------------------------',
	'^.\\w+ Domain .* Whois service',
	'^Copyright by .* Domain LTD',
	'^----------------------------------',
	'^Database last updated',
    ],
    'whois.dotmobiregistry.net' => [
	'^mTLD WHOIS LEGAL STATEMENT',
	'^by mTLD and the access to',
	'^for information purposes only.',
	'^domain name is still available',
	'^the registration records of',
	'^circumstances, be held liable',
	'^be wrong, incomplete, or not',
	'^you agree not to use the information',
	'^otherwise support the transmission',
	'^other solicitations whether via',
	'^possible way; or to cause',
	'^sending \(whether by automated,',
	'^volumes or other possible means\)',
	'^above, it is explicitly forbidden',
	'^in any form and by any means',
	'^quantitatively or qualitatively',
	'^database without prior and explicit',
	'^hereof, or to apply automated,',
	'^You agree that any reproduction',
	'^purposes will always be considered',
	'^the content of the WHOIS database.',
	'^by this policy and accept that mTLD',
	'^WHOIS services in order to protect',
	'^integrity of the database.',
    ],
    'whois.godaddy.com' => [
	'^The data contained in GoDaddy.com,',
	'^while believed by the company to be',
	'^with no guarantee or warranties',
	'^information is provided for the sole',
	'^in obtaining information about domain',
	'^Any use of this data for any other',
	'^permission of GoDaddy.com, Inc.',
	'^you agree to these terms of usage',
	'^you agree not to use this data to',
	'^dissemination or collection of this',
	'^purpose, such as the transmission of',
	'^and solicitations of any kind, including',
	'^not to use this data to enable high volume,',
	'^processes designed to collect or compile',
	'^including mining this data for your own',
	'^Please note: the registrant of the domain',
	'^in the "registrant" field.  In most cases,',
	'^is not the registrant of domain names listed',
    ],
    'whois.paycenter.com.cn' => [
	'^The Data in Paycenter\'s WHOIS database is',
	'^for information purposes, and to assist',
	'^information about or related to a domain',
	'^record\.',
	'^Paycenter does not guarantee its accuracy.',
	'^a WHOIS query, you agree that you will use',
	'^for lawful purposes and that, under no',
	'^you use this Data to:',
	'^\(1\) allow, enable, or otherwise support',
	'^of mass unsolicited, commercial',
	'^via e-mail \(spam\); or',
	'^\(2\) enable high volume, automated,',
	'^apply to Paycenter or its systems.',
	'^Paycenter reserves the right to modify',
	'^By submitting this query, you agree to',
    ],
    'whois.enom.com' => [
	'^=-=-=-=',
	'^The data in this whois database is provided',
	'^purposes only, that is, to assist you in',
	'^related to a domain name registration record.',
	'^available "as is," and do not guarantee its',
	'^whois query, you agree that you will use this',
	'^purposes and that, under no circumstances will',
	'^enable high volume, automated, electronic',
	'^this whois database system providing you this',
	'^enable, or otherwise support the transmission',
	'^commercial advertising or solicitations via',
	'^mail, or by telephone. The compilation,',
	'^other use of this data is expressly',
	'^consent from us.',
	'^We reserve the right to modify these',
	'^this query, you agree to abide by these',
	'^Version ',
	'^<a href="',
    ],
    'whois.dotster.com' => [
	'^The information in this whois database is',
	'^purpose of assisting you in obtaining',
	'^name registration records. This information',
	'^and we do not guarantee its accuracy. By',
	'^query, you agree that you will use this',
	'^purposes and that, under no circumstances',
	'^to: \(1\) enable high volume, automated,',
	'^stress or load this whois database system',
	'^information; or \(2\) allow,enable, or',
	'^transmission of mass, unsolicited, commercial',
	'^solicitations via facsimile, electronic mail,',
	'^entitites other than your own existing customers.',
	'^compilation, repackaging, dissemination or other',
	'^is expressly prohibited without prior written',
	'^company. We reserve the right to modify these',
	'^time. By submitting an inquiry, you agree to',
	'^and limitations of warranty.  Please limit',
	'^minute and one connection.',
    ],
    'whois.nordnet.net' => [
	'^Serveur Whois version',
	'^\*\*\*\*\*\*\*\*\*',
	'^\* Base de Donnees des domaines COM, NET et ORG',
	'^\* enregistres par NORDNET.                    ',
	'^\* Ces informations sont affichees par le serve',
	'^\* Whois de NORDNET, le Registrar du           ',
	'^\* Groupe FRANCE-TELECOM                       ',
	'^\* Elles ne peuvent etre utilisees sans l accor',
	'^\* prealable de NORDNET.                       ',
	'^\*                                             ',
	'^\* Database of registration for COM, NET and   ',
	'^\* ORG by NORDNET.                             ',
	'^\* This informations is from NORDNET s Whois   ',
	'^\* Server, the Registrar for the               ',
	'^\* Group FRANCE-TELECOM.                       ',
	'^\* Use of this data is strictly prohibited with',
	'^\* out proper authorisation of NORDNET.',
	'^Deposez votre domaine sur le site http://www.nordnet.net',
	'^Copyright Nordnet Registrar',
    ],
);

our %exceed = (
    'whois.eu' => 'Excessive querying, grace period of',
    'whois.dns.lu' => 'Excessive querying, grace period of',
    'whois.mynic.net.my' => 'Query limitation is',
    'whois.ripn.net' => 'exceeded allowed connection rate',
    'whois.domain-registry.nl' => 'too many requests',
    'whois.nic.uk' => 'and will be replenished',
);

our $default_ban_time = 60;
our %ban_time = (
    'whois.ripn.net'  => 60,
);

our %postprocess = (
    'whois.net.ua' => sub {  },
);

1;
