package Mail::SpamAssassin::Plugin::URIHash;
my $VERSION = 0.02;

### About:
#
# This plugin creates rbl style DNS lookups for URIs, which are turned
# into md5hash.
#

### Install:
#
# Please add loadplugin to custom.pre (so it's loaded before cf files!):
#
# loadplugin Mail::SpamAssassin::Plugin::URIHash URIHash.pm
#

### Supported .cf clauses:
#
# urihash_acl_<aclname> domain ...
#
#    Where <aclname> is 1-32 character alphanumeric (a-z0-9) identifier.
#    No wildcards or subdomains of any kind, everything must be literal.
#
#    Path to parse is set with urihash_path_<aclname>, only URIs matching
#    this will be hashed.
#
#    urihash_path_shorteners [/?](?:[a-z0-9_.?=-]|(?:%[0-9a-f][0-9a-f])){2,64}
#    urihash_acl_shorteners bit.ly snurl.com docs.google.com/doc
#
# header URIHASH_TEST eval:check_urihash('aclname', 'zone' [, 'sub-test'])
# tflags URIHASH_TEST net
#
#    First argument is <aclname>. Special acl of 'all' can be used to allow
#    lookup every URI (do not use unless used uribl allows it!).
#
#    No more than 3 unique matching URIs are collected from body.
#
#    'Zone' is the DNS zone, e.g. 'uribl.example.com.' (customary to add ending dot)
#
#    'Sub-test' is regex matching the returned IP address, e.g. '127.0.0.[234]'.
#    It defaults to '127\.\d+\.\d+\.\d+' (anything starting with 127).
#
#    There is no limit on mixing and matching multiple check_urihash rules,
#    acls and zones.
#

### Changelog:
#
# 0.01 - first internal version
#

### License:
#
# Author: Henrik Krohns <sa@hege.li>
# Copyright 2010 Henrik Krohns
#
# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#

use strict;
use Mail::SpamAssassin::Plugin;
use Net::DNS;
use Digest::MD5 qw(md5_hex);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("URIHash: @_"); }

sub new
{
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->{URIHash_available} = 1;
    if ($mailsa->{local_tests_only}) {
        $self->{URIHash_available} = 0;
        dbg("only local tests enabled, plugin disabled");
    }

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_urihash");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds = ();
    push(@cmds, {
        setting => 'urihash_add_describe_uri',
        default => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
    my ($self, $opts) = @_;

    if ($opts->{key} =~ /^urihash_acl_([a-z0-9]{1,32})$/i) {
        $self->inhibit_further_callbacks();
        return 1 unless $self->{URIHash_available};

        my $acl = lc($1);
        foreach my $temp (split(/\s+/, $opts->{value}))
        {
            if ($temp =~ /^([a-z0-9._\/-]+)$/i) {
                my $domain = lc($1);
                $domain =~ s/\./\\./g;
                push @{$self->{urihash_domains}{$acl}}, $domain;
            }
            else {
                warn("invalid acl: $temp");
            }
        }

        return 1;
    }
    elsif ($opts->{key} =~ /^urihash_path_([a-z0-9]{1,32})$/i) {
        $self->inhibit_further_callbacks();
        return 1 unless $self->{URIHash_available};

        my $acl = lc($1);
        eval { qr/$opts->{value}/; };
        if ($@) {
            warn("invalid path regex for $acl: $@");
            return 0;
        }
        $self->{urihash_path}{$acl} = $opts->{value};

        return 1;
    }

    return 0;
}

sub finish_parsing_end {
    my ($self, $opts) = @_;

    return 0 unless $self->{URIHash_available};

    foreach my $acl (keys %{$self->{urihash_domains}}) {
        unless (defined $self->{urihash_path}{$acl}) {
            warn("missing urihash_path_$acl definition");
            next;
        }
        my $restr = '(?<![a-z0-9.-])'.
                    '('.join('|', @{$self->{urihash_domains}{$acl}}).')'.
                    '('.$self->{urihash_path}{$acl}.')';
        my $re = eval { qr/$restr/i; };
        if ($@) {
            warn("invalid regex for $acl: $@");
            next;
        }
        dbg("re: $re");
        $self->{urihash_re}{$acl} = $re;
    }

    my $recnt = scalar keys %{$self->{urihash_re}};
    dbg("loaded $recnt acls");

    return 0;
}

# parse eval rule args
sub _parse_args {
    my ($self, $acl, $zone, $zone_match) = @_;

    if (not defined $zone) {
        warn("acl and zone must be specified for rule");
        return ();
    }

    # acl
    $acl =~ s/\s+//g; $acl = lc($acl);
    if ($acl !~ /^[a-z0-9]{1,32}$/) {
        warn("invalid acl definition: $acl");
        return ();
    }
    if ($acl ne 'all' and not defined $self->{urihash_re}{$acl}) {
        warn("no such acl defined: $acl");
        return ();
    }

    # zone
    $zone =~ s/\s+//g; $zone = lc($zone);
    unless ($zone =~ /^[a-z0-9_.-]+$/) {
        warn("invalid zone definition: $zone");
        return ();
    }

    # zone_match
    if (defined $zone_match) {
        my $tst = eval { qr/$zone_match/ };
        if ($@) {
            warn("invalid match regex: $zone_match");
            return ();
        }
    }
    else {
        $zone_match = '127\.\d+\.\d+\.\d+';
    }

    return ($acl, $zone, $zone_match);
}

sub _add_desc {
    my ($self, $pms, $uri, $desc) = @_;

    my $rulename = $pms->get_current_eval_rule_name();
    if (not defined $pms->{conf}->{descriptions}->{$rulename}) {
        $pms->{conf}->{descriptions}->{$rulename} = $desc;
    }
    if ($pms->{main}->{conf}->{urihash_add_describe_uri}) {
        #$email =~ s/\@/[at]/g; TODO
        $pms->{conf}->{descriptions}->{$rulename} .= " ($uri)";
    }
}
                                                
# hash and lookup array of uris
sub _lookup {
    my ($self, $pms, $prs, $uris) = @_;

#    return 0 unless defined @$uris;
    return 0 unless @$uris;

    my %digests = map { md5_hex($_) => $_ } @$uris;
    my $dcnt = scalar keys %digests;

    # nothing to do?
    return 0 unless $dcnt;

    # todo async lookup and proper timeout
    my $timeout = int(10 / $dcnt);
    $timeout = 3 if $timeout < 3;

    my $resolver = Net::DNS::Resolver->new(
        udp_timeout => $timeout,
        tcp_timeout => $timeout,
        retrans => 0,
        retry => 1,
        persistent_tcp => 0,
        persistent_udp => 0,
        dnsrch => 0,
        defnames => 0,
    );

    foreach my $digest (keys %digests) {
        my $uri = $digests{$digest};

        # if cached
        if (defined $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"}) {
            my $addr = $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"};
            dbg("lookup: $digest.$prs->{zone} ($uri) [cached]");
            return 0 if ($addr eq '');
            if ($addr =~ $prs->{zone_match}) {
                dbg("HIT! $digest.$prs->{zone} = $addr ($uri)");
                $self->_add_desc($pms, $uri, "URIHash hit at $prs->{zone}");
                return 1;
            }
            return 0;
        }

        dbg("lookup: $digest.$prs->{zone} ($uri)");
        my $query = $resolver->query("$digest.$prs->{zone}", 'A');
        if (not defined $query) {
            if ($resolver->errorstring ne 'NOERROR' &&
                $resolver->errorstring ne 'NXDOMAIN') {
                dbg("DNS error? ($resolver->{errorstring})");
            }
            $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"} = '';
            next;
        }
        foreach my $rr ($query->answer) {
            if ($rr->type ne 'A') {
                dbg("got answer of wrong type? ($rr->{type})");
                next;
            }
            if (defined $rr->address && $rr->address ne '') {
                $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"} = $rr->address;
                if ($rr->address =~ $prs->{zone_match}) {
                    dbg("HIT! $digest.$prs->{zone} = $rr->{address} ($uri)");
                    $self->_add_desc($pms, $uri, "URIHash hit at $prs->{zone}");
                    return 1;
                }
                else {
                    dbg("got answer, but not matching $prs->{zone_match} ($rr->{address})");
                }
            }
            else {
                dbg("got answer but no IP? ($resolver->{errorstring})");
            }
        }
    }

    return 0;
}

sub _urihash {
    my ($self, $pms, $acl, $zone, $zone_match) = @_;

    my $prs = {}; # per rule state
    $prs->{acl} = $acl;
    $prs->{zone} = $zone;
    $prs->{zone_match} = $zone_match;
    $prs->{rulename} = $pms->get_current_eval_rule_name();

    dbg("RULE ($prs->{rulename}) acl:$acl zone:$zone match:${zone_match}");

    my %uris;

    my $parsed = $pms->get_uri_detail_list();
    while (my($uri, $info) = each %{$parsed}) {
        if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
            if ($uri =~ $self->{urihash_re}{$acl}) {
                my $domain = lc($1);
                my $path = $2;
                $path =~ s/%([a-f0-9]{2})/chr(hex($1))/eig;
                $uris{"$domain$path"} = 1;
                last if scalar keys %uris >= 3;
            }
        }
    }

    my $body = $pms->get_decoded_body_text_array();
    BODY: foreach (@$body) {
        while (/$self->{urihash_re}{$acl}/g) {
            my $domain = lc($1);
            my $path = $2;
            $path =~ s/%([a-f0-9]{2})/chr(hex($1))/eig;
            $uris{"$domain$path"} = 1;
            last BODY if scalar keys %uris >= 6;
        }
    }

    my @lookups = keys %uris;
    return $self->_lookup($pms, $prs, \@lookups);
}

sub check_urihash {
    my ($self, $pms, @args) = @_;

    shift @args;

    return 0 unless $self->{URIHash_available};
    return 0 unless (@args = $self->_parse_args(@args));
    return _urihash($self, $pms, @args);
}

1;
