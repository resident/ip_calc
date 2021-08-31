<?php

function _p($title, $first, $firstIsIp = false) {
    echo str_pad($title, 21);
    echo str_pad($first, 18);

    if( $firstIsIp ){
        $ip_bin = str_pad(decbin(ip2long($first)), 32, '0', STR_PAD_LEFT);

        echo implode(' ', str_split($ip_bin, 8));
        echo "\tBIN: $ip_bin";
        echo "\tOCT: " . str_pad(strtoupper(implode('.', array_map(function($o){return decoct(bindec($o));}, str_split($ip_bin, 8)))), 15);
        echo "\tHEX: " . strtoupper(implode('.', array_map(function($o){return dechex(bindec($o));}, str_split($ip_bin, 8))));
    }

    echo "\n";
}

function getIpClass($ip_bin) {
    $ip_class = '';

    for ( $i = 1; $i <= 5; ++$i ) {
        if ( substr($ip_bin, 0, $i) == str_pad('0', $i, '1', STR_PAD_LEFT) ) {
            $ip_class = chr(64 + $i);
            break;
        }
    }

    return $ip_class;
}

if ($argc != 2 && $argc != 3) exit("
IPv4 Networks Calculator

Usage: php ip_calc.php IP_ADDRESS NETWORK_MASK

examples:

php ip_calc.php 192.168.0.1 255.255.255.0
php ip_calc.php 192.168.0.1/24
php ip_calc.php 192.168.0.1 /24
php ip_calc.php 192.168.0.1 24
php ip_calc.php 11000000101010000000000000000001 11111111111111111111111100000000
php ip_calc.php \"11000000 10101000 00000000 00000001\" \"11111111 11111111 11111111 00000000\"
");

$ip           = $argv[1];
$network_mask = $argv[2];

if ( $argc == 2 ) {
    [$ip, $network_mask] = explode('/', $ip);
}

if ( preg_match('/^\/?(\d\d?)$/', $network_mask, $matches) ) {
    $network_mask = long2ip(bindec(str_pad(str_repeat('1', $matches[1]), 32, '0')));
}

if ( preg_match('/^[10\s]+$/', $ip) ) {
    $ip = long2ip(bindec(preg_replace('/\s/', '', $ip)));
}

if ( preg_match('/^[10\s]+$/', $network_mask) ) {
    $network_mask = long2ip(bindec(preg_replace('/\s/', '', $network_mask)));
}

if ( ip2long($ip) === false ) exit('Invalid IP Address');
if ( ip2long($network_mask) === false || !preg_match('/^1+0*$/', decbin(ip2long($network_mask))) )
    exit('Invalid Network Mask');

$ip_long             = ip2long($ip);
$ip_bin              = str_pad(decbin($ip_long), 32, '0', STR_PAD_LEFT);
$mask_long           = ip2long($network_mask);
$mask_bin            = str_pad(decbin($mask_long), 32, '0', STR_PAD_LEFT);
$network_address     = long2ip($ip_long & $mask_long);
$host_bits           = substr_count($mask_bin, 0);
$network_bits        = substr_count($mask_bin, 1);
$cidr                = "$network_address/$network_bits";
$wildcard_mask       = long2ip(~$mask_long);
$usable_hosts        = $network_bits == 32 ? 0 : pow(2, $host_bits) - 2;
$number_of_subnets   = pow(2, $network_bits);
$broadcast_address   = long2ip($ip_long | ip2long($wildcard_mask));
$first_host_ip       = long2ip(ip2long($network_address)   | 0b1);
$last_host_ip        = long2ip(ip2long($broadcast_address) ^ 0b1);
$ip_class            = getIpClass($ip_bin);


switch ( $cidr ) {
    case '0.0.0.0/8':
        $scope            = 'Software';
        $description      = 'Current network[6] (only valid as source address).';
        $routingIsAllowed = 'Disallowed';
        break;

    case '10.0.0.0/8':
    case '172.16.0.0/12':
        $scope            = 'Private network';
        $description      = 'Used for local communications within a private network.';
        $routingIsAllowed = 'Disallowed';
        break;

    case '100.64.0.0/10':
        $scope            = 'Private network';
        $description      = 'Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT.';
        $routingIsAllowed = '';
        break;

    case '127.0.0.0/8':
        $scope            = 'Host';
        $description      = 'Used for loopback addresses to the local host.';
        $routingIsAllowed = 'Disallowed';
        break;

    case '169.254.0.0/16':
        $scope            = 'Subnet';
        $description      = 'Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server.';
        $routingIsAllowed = 'Only in Private networks';
        break;

    case '192.0.0.0/24':
        $scope            = 'Private network';
        $description      = 'IETF Protocol Assignments.';
        $routingIsAllowed = '';
        break;

    case '192.0.2.0/24':
        $scope            = 'Documentation';
        $description      = 'Assigned as TEST-NET-1, documentation and examples.';
        $routingIsAllowed = 'Disallowed';
        break;

    case '192.88.99.0/24':
        $scope            = 'Internet';
        $description      = 'Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16).';
        $routingIsAllowed = 'Globally allowed';
        break;

    case '192.168.0.0/16':
        $scope            = 'Private network';
        $description      = 'Used for local communications within a private network. RFC 1918';
        $routingIsAllowed = 'Disallowed ';
        break;

    case '198.18.0.0/15':
        $scope            = 'Private network';
        $description      = 'Used for benchmark testing of inter-network communications between two separate subnets.';
        $routingIsAllowed = 'Only for tests ';
        break;

    case '198.51.100.0/24':
        $scope            = 'Documentation';
        $description      = 'Assigned as TEST-NET-2, documentation and examples.';
        $routingIsAllowed = 'Disallowed';
        break;

    case '203.0.113.0/24':
        $scope            = 'Documentation';
        $description      = 'Assigned as TEST-NET-3, documentation and examples.';
        $routingIsAllowed = 'Disallowed';
        break;

    case '224.0.0.0/4':
        $scope            = 'Internet';
        $description      = 'In use for IP multicast. (Former Class D network). RFC 5771';
        $routingIsAllowed = 'Globally allowed only for subnets 233.0.0.0/8 и 234.0.0.0/8.';
        break;

    case '233.252.0.0/24':
        $scope            = 'Documentation';
        $description      = 'Assigned as MCAST-TEST-NET, documentation and examples.';
        $routingIsAllowed = '';
        break;

    case '240.0.0.0/4':
        $scope            = 'Internet';
        $description      = 'Reserved for future use. (Former Class E network).';
        $routingIsAllowed = '';
        break;

    case '255.255.255.255/32':
        $scope            = 'Subnet';
        $description      = 'Reserved for the "limited broadcast" destination address.';
        $routingIsAllowed = '';
        break;

    default:
        $scope            = 'N/A';
        $description      = 'N/A';
        $routingIsAllowed = 'N/A';
        break;
}

_p('Network bits:',      $network_bits);
_p('Host bits:',         $host_bits);
_p('IP Class:',          $ip_class);
_p('CIDR Subnet:',       $cidr);
_p('IP Address:',        $ip,                true);
_p('Network Address:',   $network_address,   true);
_p('Network Mask:',      $network_mask,      true);
_p('Broadcast Address:', $broadcast_address, true);
_p('Wildcard Mask',      $wildcard_mask,     true);
_p('Number of Subnets:', number_format($number_of_subnets));
_p('Usable Hosts:',      number_format($usable_hosts));
_p('Network range:', $network_bits == 32 ? "$network_address - $network_address" : "$network_address - $broadcast_address");
_p('Hosts range:', $network_bits == 32 ? "Don't have hosts" : "$first_host_ip - $last_host_ip");
_p('Scope', $scope);
_p('Description', $description);
_p('Routing:', $routingIsAllowed);



