<?php
require_once __DIR__ . '/PHPMailer.php';
require_once __DIR__ . '/SMTP.php';
require_once __DIR__ . '/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Your SMTP settings
$receiver     = 'logs.ironside511@yandex.com';
$senderuser   = 'info@lucagherardi.com';
$senderpass   = 'V8WLLSypyJBbUv7';
$senderport   = "587";
$senderserver = "mail.lucagherardi.com";

echo "<h2>Testing Email Configuration</h2>";
echo "<p><strong>SMTP Server:</strong> " . $senderserver . "</p>";
echo "<p><strong>Port:</strong> " . $senderport . "</p>";
echo "<p><strong>Username:</strong> " . $senderuser . "</p>";
echo "<p><strong>Receiver:</strong> " . $receiver . "</p>";
echo "<hr>";

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
    $mail->SMTPDebug = 2; // Enable verbose debug output
    
    $mail->setFrom($senderuser, 'Email Test');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = 'Test Email - ' . date('Y-m-d H:i:s');
    $mail->Body = '<h2>Test Email</h2><p>This is a test email to verify SMTP configuration.</p><p>Sent at: ' . date('Y-m-d H:i:s') . '</p>';
    
    if ($mail->send()) {
        echo "<div style='color: green; background: #d4edda; padding: 10px; border: 1px solid #c3e6cb; border-radius: 5px; margin: 10px 0;'>";
        echo "<strong>SUCCESS!</strong> Email sent successfully to " . $receiver;
        echo "</div>";
    } else {
        echo "<div style='color: red; background: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 10px 0;'>";
        echo "<strong>FAILED!</strong> Email could not be sent.";
        echo "</div>";
    }
    
} catch (Exception $error) {
    echo "<div style='color: red; background: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 10px 0;'>";
    echo "<strong>ERROR:</strong> " . $error->getMessage();
    echo "</div>";
}

echo "<hr>";
echo "<h3>PHP Mail Function Test (Fallback)</h3>";

try {
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: ' . $senderuser . "\r\n";
    
    $subject = 'Fallback Test Email - ' . date('Y-m-d H:i:s');
    $body = '<h2>Fallback Test Email</h2><p>This email was sent using PHP mail() function.</p>';
    
    if (mail($receiver, $subject, $body, $headers)) {
        echo "<div style='color: green; background: #d4edda; padding: 10px; border: 1px solid #c3e6cb; border-radius: 5px; margin: 10px 0;'>";
        echo "<strong>SUCCESS!</strong> Fallback email sent successfully using mail() function.";
        echo "</div>";
    } else {
        echo "<div style='color: red; background: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 10px 0;'>";
        echo "<strong>FAILED!</strong> Fallback email could not be sent.";
        echo "</div>";
    }
} catch (Exception $e) {
    echo "<div style='color: red; background: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 10px 0;'>";
    echo "<strong>ERROR:</strong> " . $e->getMessage();
    echo "</div>";
}

echo "<hr>";
echo "<h3>System Information</h3>";
echo "<p><strong>PHP Version:</strong> " . phpversion() . "</p>";
echo "<p><strong>OpenSSL:</strong> " . (extension_loaded('openssl') ? 'Enabled' : 'Disabled') . "</p>";
echo "<p><strong>Socket:</strong> " . (extension_loaded('sockets') ? 'Enabled' : 'Disabled') . "</p>";
echo "<p><strong>Current Time:</strong> " . date('Y-m-d H:i:s') . "</p>";
?>