<?php

$cadir = 'demoCA';
$config = 'openssl.cnf';

function create_cert($countryName, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName, $commonName, $emailAddress, $pubkey) {
	global $cadir, $config;

	// Remove any whitespace in the supplied SPKAC
	$keyreq = "SPKAC=" . str_replace(str_split(" \t\n\r\0\x0B"), '', $pubkey);

	// Create the DN for the openssl call
	if ($countryName)
	$keyreq .= "\ncountryName=" . $countryName;

	if ($stateOrProvinceName)
	$keyreq .= "\nstateOrProvinceName=" . $stateOrProvinceName;

	if ($localityName)
	$keyreq .= "\nlocalityName=" . $localityName;

	if ($organizationName)
	$keyreq .= "\norganizationName=" . $organizationName;

	if ($organizationalUnitName)
	$keyreq .= "\n0.OU=" . $organizationalUnitName;

	if ($commonName)
	$keyreq .= "\nCN=" . $commonName;

	if ($emailAddress)
	$keyreq .= "\nemailAddress=" . $emailAddress;

	// Create temporary files to hold the input and output to the openssl call.
	$spkac = 'spkac/'.md5(time().rand()).'.spkac';
	$p12_file = md5(time() . rand()).'.p12';
	$p12 = 'p12/'.$p12_file;

	// Write the SPKAC and DN into the temporary file
	file_put_contents($cadir.'/'.$spkac, $keyreq);

	$command = '(cd "'.$cadir.'" ; openssl ca -config "'.$config.'" -verbose -batch -notext -spkac "'.$spkac.'" -out "'.$p12.'" 2>&1)';

	// Run the command;
	$output = shell_exec($command);
	#echo "<pre>$output</pre>";

	// Delete the temporary SPKAC file
	unlink($cadir.'/'.$spkac);

	if (preg_match("/Data Base Updated/", $output) == 0) {
		echo "<pre>";
		echo '$ '.$command."\n";
		echo $output;
		echo "</pre>";
		return;
	}

	return $p12_file;
}

function inst_cert($p12) {
	// Send the p12 encoded SSL certificate
	global $cadir;
	$length = filesize($p12);
	header('Last-Modified: ' . date('r+b'));
	header('Accept-Ranges: bytes');
	header('Content-Length: ' . $length);
	header('Content-Type: application/x-x509-user-cert');
	readfile($p12);
	exit;
}

if ($_POST['genCert']) {  
	// Get the rest of the script parameters
	$commonName = $_POST['commonName'];
	$countryName = $_POST['countryName'];
	$stateOrProvinceName = $_POST['stateOrProvinceName'];
	$localityName = $_POST['localityName'];
	$organizationName = $_POST['organizationName'];
	$organizationalUnitName = $_POST['organizationalUnitName'];
	$emailAddress = $_POST['emailAddress'];
	$pubkey = $_POST['pubkey'];

	// Create a x509 SSL certificate
	if ($p12_file = create_cert($countryName, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName, $commonName, $emailAddress, $pubkey)) {
		inst_cert($cadir.'/p12/'.$p12_file);
		#echo '<a href="keygen.php?install='.$p12_file.'">Install</a>';
	}
	else {
		echo "error creating cert";
	}
}
else if ($_GET['install']) {
	if(preg_match("/\.\./", $_GET['install']) == 0) {
		inst_cert($cadir.'/p12/'.$_GET['install']);
	}
}
else {
	echo '
	<form action="/cert/keygen.php" method="post" enctype="multipart/form-data">
		<table>
			<tr>
				<td>Key size: </td>
				<td><keygen name="pubkey"></td>
			</tr>
			<tr>
				<td>commonName: </td>
				<td><input type="text" name="commonName" value=""/></td>
			</tr>
			<tr>
				<td>Email: </td>
				<td><input type="text" name="emailAddress" value="no@thank.you"/></td>
			</tr>
			<tr>
				<td>organizationName: </td>
				<td><input type="text" name="organizationName" value="Open Web"/></td>
			</tr>
			<tr>
				<td>organizationalUnitName: 
				<td><input type="text" name="organizationalUnitName" value="HTML5 Users (English)"/></td>
			<tr>
				<td>localityName: 
				<td><input type="text" name="localityName" value="Seoul"/></td>
			<tr>
				<td>stateOrProvinceName: 
				<td><input type="text" name="stateOrProvinceName" value="South Korea"/></td>
			<tr>
				<td>countryName: 
				<td><input type="text" name="countryName" value="KR"/></td>
			<tr>
				<td colspan="2">
					<input type="hidden" name="genCert" value="1"/>
					<input type=submit value="Submit key...">
				</td>
			</tr>
		</table>
	</form>
	<!--<a href="/cert/demoCA/root.crt">root.crt</a>-->
	';
}
?>
