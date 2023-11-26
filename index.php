<?php
if(!file_exists("./cache/cache.rw")){
	if(is_file("./cache") && !is_dir("./cache")){
		unlink("./cache");
		mkdir("./cache",0777,true);
	}else{
		file_put_contents("./cache/cache.rw","RW");
	}
}else{
	mkdir("./cache",0777,true);
}
session_cache_limiter('public');
session_cache_expire(5);

/* Domain str to DNS raw qname */
function doh_domain2raw($domainname)
{
	$raw = "";
	$domainpieces = explode('.', $domainname);
	foreach($domainpieces as $domainbit)
	{
		$raw = $raw.chr(strlen($domainbit)).$domainbit;
	}
	$raw = $raw.chr(0);
	return($raw);
}
function doh_raw2domain($qname)
{
	$mylenght = ord($qname[0]);
	$domainname = "";
	$i = 1;
	while(1)
	{
		while($mylenght)
		{
			$domainname = $domainname.$qname[$i++];
			$mylenght--;
		}
		$mylenght = ord($qname[$i]);
		$i++;

		if($mylenght == 0)
		{
			break;
		}
		else if($mylenght == 192)
		{
			break;
		}
		$domainname = $domainname.".";
	}
	return($domainname);
}


/* DNS type names to raw types */
function doh_get_qtypes($requesttype = "A")
{
	switch($requesttype){
		case "AAAA":
			$rawtype = 28;
			break;
		case "CNAME":
			$rawtype = 5;
			break;
		case "NS":
			$rawtype = 2;
			break;
		default:
			$rawtype = 1;
			break;
	}
	return($rawtype);
}


/* Generate a DNS raw query */
function doh_generate_dnsquery($domainname, $requesttype="A")
{
	$rawtype = doh_get_qtypes($requesttype);
	$dns_query  = sprintf("\xab\xcd").chr(1).chr(0).
				  chr(0).chr(1).  /* qdc */
				  chr(0).chr(0).  /* anc */
				  chr(0).chr(0).  /* nsc */
				  chr(0).chr(0).  /* arc */
				  doh_domain2raw($domainname). 
				  chr(0).chr($rawtype). 
				  chr(0).chr(1);  /* qclass */
	return($dns_query);
}
function doh_get_requesttype($raw){
	return ord($raw[-3]);
}
function doh_getdomain_dnsquery($raw)
{
	$domain = '';
	$n = 0;
	while(true){
		$b = ord($raw[12+$n]);
		if($b != 0){
			$domain .= substr($raw,13+$n,$b).".";
			$n += $b+1;
		}else{
			break;
		}
	}
	return substr($domain,0,(strlen($domain)-1));
}


/* base64url encode the request */
function doh_encoderequest($request)
{
	return(str_replace("=", "", base64_encode($request)));
}
/* Connects via HTTPS to remote DoH servers */
function doh_connect_https($dnsquery)
{
	$ch = curl_init();
	$headers = array('Accept: application/dns-message',"Content-Type: application/dns-message");
	//, 'Content-type: application/dns-udpwireformat');
	curl_setopt($ch, CURLOPT_URL, "https://cloudflare-dns.com/dns-query"); // support POST
	curl_setopt($ch, CURLOPT_POSTFIELDS, $dnsquery);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_USERAGENT, 'DOH-Client-PHP');
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); // true (or 1) removed in curl 7.28.1
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($ch, CURLOPT_TIMEOUT, 10);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$output = curl_exec($ch);
	if($output === FALSE)
	{
		return(null);
	}
	return($output);
}

/* Parses DNS raw answers. */
function doh_read_dnsanswer($raw, $requesttype)
{
	$results = array();
	$raw_counter = 0;
	$rawtype = doh_get_qtypes($requesttype);
	/* Getting header. */
	$qst_header = unpack("nid/nspec/nqdcount/nancount/nnscount/narcount", substr($raw, $raw_counter, 12));
	$raw_counter += 12;
	if($qst_header['ancount'] == 0)
		return($results);
	$domainresp = doh_raw2domain(substr( $raw, $raw_counter));

	$raw_counter += strlen($domainresp) + 2;
	$rawtype = ord($raw[$raw_counter + 7]);

	$ans_header = unpack("ntype/nclass/Nttl/nlength", substr( $raw, $raw_counter, 10 ) );
	$raw_counter += 13;

	/* Jumping to the IP address */
	$raw_counter += 3;

	$iplength = 4;
	if($rawtype === 28)
	{
		$iplength = 16;
	}

	if($rawtype == 1 || $rawtype == 28)
	{
		$result_ip = inet_ntop(substr( $raw, $raw_counter, $iplength ));
		if($rawtype == 1)
			$results['ipv4'][] = $result_ip;
		else
			$results['ipv6'][] = $result_ip;
		/* Looping through all answers */
		if($qst_header['ancount'] > 1)
		{
			$i = 1;
			while($i < $qst_header['ancount'])
			{
				$raw_counter += $iplength;
				$raw_counter += 12;
				if($rawtype == 1)
					$results['ipv4'][] = inet_ntop(substr( $raw, $raw_counter , $iplength ));
				else
					$results['ipv6'][] = $result_ip;
				$i++;
			}
		}
	}
	else if($rawtype == 5)
	{
		$domainresp = doh_raw2domain(substr( $raw, $raw_counter));
		$results['cname'][] = $domainresp;
	}
	return($results);
}
$raw = file_get_contents("php://input");
if(strlen($raw) == 0)
	die();
$domain = doh_getdomain_dnsquery($raw);
$type = doh_get_requesttype($raw);
$list = json_decode(file_get_contents("config.json"),true);
if(in_array($domain, $list["block"]))
	die(0);
$dnsrawresults = doh_connect_https($raw);
$cache_domain = "./cache/".md5($domain).".cache";
if(!file_exists($cache_domain))
	file_put_contents($cache_domain,$dnsrawresults);
header("Content-Type: application/dns-message");
header("Cache-Control: max-age=300, s-maxage=300");
header("Connection: keep-alive");

$lastModified = filemtime($cache_domain);
$etagFile = md5_file($cache_domain);

header("Last-Modified: ". gmdate("D, d M Y H:i:s", $lastModified) ." GMT");
header("Etag: $etagFile");


$ifModifiedSince=(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? $_SERVER['HTTP_IF_MODIFIED_SINCE'] : false);
$etagHeader=(isset($_SERVER['HTTP_IF_NONE_MATCH']) ? trim($_SERVER['HTTP_IF_NONE_MATCH']) : false);
if (@strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE'])==$lastModified || $etagHeader==$etagFile )
{
	header("HTTP/1.1 304 Not Modified");
	die();
}
file_put_contents($cache_domain,$dnsrawresults);
echo $dnsrawresults;
?>
