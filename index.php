<?php

/**
 * Sign MobileConfig
 *
 * @string $file_full_pathname   e.g. /tmp/example.mobileconfig
 * @string $certificate_pathname
 * @string $private_key_pathname
 * @string $chain_pathname
 * @bool   $replace_file          Optional, default is true, if you want to keep your unsigned file then set to false.
 *
 * @return string
 */
function signMobileConfig(
    string $file_full_pathname,
    string $certificate_pathname,
    string $private_key_pathname,
    string $chain_pathname,
    bool $replace_file = true
): void {
    $signed_name = basename($file_full_pathname, ".mobileconfig") . "_signed.mobileconfig";
    $base_directory = dirname($file_full_pathname);
    $signed_path = $base_directory . DIRECTORY_SEPARATOR . $signed_name;

    // Signing code based on https://stackoverflow.com/a/52888913

    function get_base64($file_name)
    {
        $content = file($file_name, FILE_IGNORE_NEW_LINES);
        $base64_data = "";
        for ($i = 5; $i < sizeof($content); $i++) { // take only the base64 chunk
            $base64_data .= $content[$i];
        }
        return $base64_data;
    }

    function pem2der($base64_data)
    {
        $der = base64_decode($base64_data);
        return $der;
    }

    if (
        openssl_pkcs7_sign(
            $file_full_pathname,
            $signed_path,
            'file://' . realpath($certificate_pathname),
            'file://' . realpath($private_key_pathname),
            array(),
            PKCS7_NOATTR,
            $chain_pathname
        )
    ) {
        $data = pem2der(get_base64($signed_path));
        $out = fopen($signed_path, "w") or die("Unable to open file!");
        fwrite($out, $data);
        fclose($out);
    }

    if ($replace_file) {
        rename($signed_path, $file_full_pathname);
    }
}

// Allowed domains for signing
$allowedDomains = ['https://dns.senkl.eu'];

// Check if origin is in allowlist
if (!in_array($_SERVER['HTTP_ORIGIN'], $allowedDomains)) {
    echo "You found the signer, good job. Unfortunately, you are not allowed to access it like this. What is this? See <a href='https://github.com/rapradiptya/dns-mobileconfig-signer/'>the README.</a>.";
    die;
}

// Set our CORS header, allowing this domain
header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $filename = uniqid() . ".mobileconfig";
    $filepath = __DIR__ . "/files/" . $filename;
    file_put_contents($filepath, file_get_contents($_FILES['data']["tmp_name"]));

    $sign = filter_var($_POST['sign'], FILTER_VALIDATE_BOOLEAN);
    if ($sign == true) {
        //On the webserver, this is where the certificates are.
        signMobileConfig($filepath, "../cert/cert.crt", "../cert/key.key", "../cert/chain.crt");
    }
    echo $filename;
} else {
    echo "You found the signer, good job. What is this? See <a href='https://github.com/rapradiptya/dns-mobileconfig-signer/'>the README.</a>.";
}
