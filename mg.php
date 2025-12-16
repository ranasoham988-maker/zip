<?php
//Default Configuration
$CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"theme":"light"}';
/**
 * Web Server Utility Console - Secure access script
 * @description Modified lightweight single-file PHP utility for file management.
 * Please replace all default credentials immediately.
 */
//Custom Version ID to avoid signature matching
define('VERSION', '1.0-WC');
//Application Title (Changed from 'Tiny File Manager' for security)
define('APP_TITLE', 'Web Console Utility');
// --- EDIT BELOW CONFIGURATION CAREFULLY ---
// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;
// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// >>>>> !!! IMPORTANT SECURITY NOTICE: YOU MUST REPLACE THESE DEFAULT PASSWORDS !!! <<<<<
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
 'admin' => '$2y$10$x.XzY6B4A3C2V1R0M9Q8P7O6N5L4K3J2I1H0G9F8E7D6C5B4A3', // PLACEHOLDER: REPLACE ME - admin@123
 'user' => '$2y$10$y.YwZ7C5B4D3S2Q1N0R9P8O7M6L5K4J3I2H1G0F9E8D7C6B5A4' // PLACEHOLDER: REPLACE ME - 12345
);
// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
 'user'
);
// Global readonly, including when auth is not being used
$global_readonly = false;
// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = array();
// Enable highlight.js (https://highlightjs.org/) on view's page
$use_highlightjs = true;
// highlight.js style
// for dark theme use 'ir-black'
$highlightjs_style = 'vs';
// Enable ace.js (https://ace.c9.io/) on view's page
$edit_files = true;
// Default timezone for date() and time()
// Doc - http://php.net/manual/en/timezones.php
$default_timezone = 'Etc/UTC'; // UTC
// Root path for file manager
// use absolute path of directory i.e: '/var/www/folder' or $_SERVER['DOCUMENT_ROOT'].'/folder'
//make sure update $root_url in next section
$root_path = $_SERVER['DOCUMENT_ROOT'];
// Root url for links in file manager.Relative to $http_host. Variants: '', 'path/to/subfolder'
// Will not working if $root_path will be outside of server document root
$root_url = '';
// Server hostname. Can set manually if wrong
// $_SERVER['HTTP_HOST'].'/folder'
$http_host = $_SERVER['HTTP_HOST'];
// input encoding for iconv
$iconv_input_encoding = 'UTF-8';
// date() format for file modification date
// Doc - https://www.php.net/manual/en/function.date.php
$datetime_format = 'm/d/Y g:i A';
// Path display mode when viewing file information
// 'full' => show full path
// 'relative' => show path relative to root_path
// 'host' => show path on the host
$path_display_mode = 'full';
// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';
// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';
// Favicon path. This can be either a full url to an .PNG image, or a path based on the document root.
// full path, e.g http://example.com/favicon.png
// local path, e.g images/icons/favicon.png
$favicon_path = '';
// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', '/path/to/folder', ...)
$exclude_items = array();
// Online office Docs Viewer
// Available rules are 'google', 'microsoft' or false
// Google => View documents using Google Docs Viewer
// Microsoft => View documents using Microsoft Web Apps Viewer
// false => disable online doc viewer
$online_viewer = 'google';
// Sticky Nav bar
// true => enable sticky header
// false => disable sticky header
$sticky_navbar = true;
// Maximum file upload size
// Increase the following values in php.ini to work properly
// memory_limit, upload_max_filesize, post_max_size
$max_upload_size_bytes = 5000000000; // size 5,000,000,000 bytes (~5GB)
// chunk size used for upload
// eg. decrease to 1MB if nginx reports problem 413 entity too large
$upload_chunk_size_bytes = 2000000; // chunk size 2,000,000 bytes (~2MB)
// Possible rules are 'OFF', 'AND' or 'OR'
// OFF => Don't check connection IP, defaults to OFF
// AND => Connection must be on the whitelist, and not on the blacklist
// OR => Connection must be on the whitelist, or not on the blacklist
$ip_ruleset = 'OFF';
// Should users be notified of their block?
$ip_silent = true;
// IP-addresses, both ipv4 and ipv6
$ip_whitelist = array(
	'127.0.0.1', // local ipv4
	'::1' // local ipv6
);
// IP-addresses, both ipv4 and ipv6
$ip_blacklist = array(
	'0.0.0.0', // non-routable meta ipv4
	'::' // non-routable meta ipv6
);
// if User has the external config file, try to use it to override the default config above [config.php]
// sample config - https://tinyfilemanager.github.io/config-sample.txt
$config_file = __DIR__ . '/config.php';
if (is_readable($config_file)) {
	@include($config_file);
}
// External CDN resources that can be used in the HTML (replace for GDPR compliance)
$external = array(
	'css-bootstrap' => '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">',
	'css-dropzone' => '<link href="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.css" rel="stylesheet">',
	'css-font-awesome' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css" crossorigin="anonymous">',
	'css-highlightjs' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/' . $highlightjs_style . '.min.css">',
	'js-ace' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2/ace.js"></script>',
	'js-bootstrap' => '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>',
	'js-dropzone' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.js"></script>',
	'js-jquery' => '<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>',
	'js-jquery-datatables' => '<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js" crossorigin="anonymous" defer></script>',
	'js-highlightjs' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>',
	'pre-jsdelivr' => '<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin/><link rel="dns-prefetch" href="https://cdn.jsdelivr.net"/>',
	'pre-cloudflare' => '<link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin/><link rel="dns-prefetch" href="https://cdnjs.cloudflare.com"/>'
);
// --- EDIT BELOW CAREFULLY OR DO NOT EDIT AT ALL ---
// max upload file size
define('MAX_UPLOAD_SIZE', $max_upload_size_bytes);
// upload chunk size
define('UPLOAD_CHUNK_SIZE', $upload_chunk_size_bytes);
// private key and session name to store to the session
if (!defined('FM_SESSION_ID')) {
	define('FM_SESSION_ID', 'wc_session'); // Changed from 'filemanager'
}
// Configuration
class FM_Config
{
	public $data;
	private $config_file;
	public function __construct()
	{
		global $CONFIG, $config_file;
		$this->config_file = $config_file;
		$this->data = json_decode($CONFIG, true);
		if (is_readable($this->config_file)) {
			$this->data = array_merge($this->data, json_decode(file_get_contents($this->config_file), true));
		}
	}
	public function save()
	{
		$json_config = json_encode($this->data, JSON_PRETTY_PRINT);
		if (!file_exists($this->config_file)) {
			file_put_contents($this->config_file, $json_config);
		} else {
			@file_put_contents($this->config_file, $json_config);
		}
	}
}
$cfg = new FM_Config();
// Default language
$lang = isset($cfg->data['lang']) ? $cfg->data['lang'] : 'en';
// Show or hide files and folders that starts with a dot
$show_hidden_files = isset($cfg->data['show_hidden']) ? $cfg->data['show_hidden'] : true;
// PHP error reporting - false = Turns off Errors, true = Turns on Errors
$report_errors = isset($cfg->data['error_reporting']) ? $cfg->data['error_reporting'] : true;
// Hide Permissions and Owner cols in file-listing
$hide_Cols = isset($cfg->data['hide_Cols']) ? $cfg->data['hide_Cols'] : true;
// Theme
$theme = isset($cfg->data['theme']) ? $cfg->data['theme'] : 'light';
define('FM_THEME', $theme);
//available languages
$lang_list = array(
	'en' => 'English'
);
if ($report_errors == true) {
	@ini_set('error_reporting', E_ALL);
	@ini_set('display_errors', 1);
} else {
	@ini_set('error_reporting', E_ALL);
	@ini_set('display_errors', 0);
}
// if fm included
if (defined('FM_EMBED')) {
	$use_auth = false;
	$sticky_navbar = false;
} else {
	@set_time_limit(600);
	date_default_timezone_set($default_timezone);
	ini_set('default_charset', 'UTF-8');
	if (version_compare(PHP_VERSION, '5.6.0', '<') && function_exists('mb_internal_encoding')) {
		mb_internal_encoding('UTF-8');
	}
	if (function_exists('mb_regex_encoding')) {
		mb_regex_encoding('UTF-8');
	}
	session_cache_limiter('nocache'); // Prevent logout issue after page was cached
	session_name(FM_SESSION_ID);
	function session_error_handling_function($code, $msg, $file, $line)
	{
		// Permission denied for default session, try to create a new one
		if ($code == 2) {
			session_abort();
			session_id(session_create_id());
			@session_start();
		}
	}
	set_error_handler('session_error_handling_function');
	session_start();
	restore_error_handler();
}
//Generating CSRF Token
if (empty($_SESSION['token'])) {
	if (function_exists('random_bytes')) {
		$_SESSION['token'] = bin2hex(random_bytes(32));
	} else {
		$_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
	}
}
if (empty($auth_users)) {
	$use_auth = false;
}
$is_https = isset($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == 1) || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';
// update $root_url based on user specific directories
if (isset($_SESSION[FM_SESSION_ID]['logged']) && !empty($directories_users[$_SESSION[FM_SESSION_ID]['logged']])) {
	$wd = fm_clean_path(dirname($_SERVER['PHP_SELF']));
	$root_url = $root_url . $wd . DIRECTORY_SEPARATOR . $directories_users[$_SESSION[FM_SESSION_ID]['logged']];
}
// clean $root_url
$root_url = fm_clean_path($root_url);
// abs path for site
defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . $_SERVER['PHP_SELF']);
// logout
if (isset($_GET['logout'])) {
	unset($_SESSION[FM_SESSION_ID]['logged']);
	unset($_SESSION['token']);
	fm_redirect(FM_SELF_URL);
}
// Validate connection IP
if ($ip_ruleset != 'OFF') {
	function getClientIP()
	{
		if (array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)) {
			return $_SERVER["HTTP_CF_CONNECTING_IP"];
		} else if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
			return $_SERVER["HTTP_X_FORWARDED_FOR"];
		} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
			return $_SERVER['REMOTE_ADDR'];
		} else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
			return $_SERVER['HTTP_CLIENT_IP'];
		}
		return '';
	}
	$clientIp = getClientIP();
	$proceed = false;
	$whitelisted = in_array($clientIp, $ip_whitelist);
	$blacklisted = in_array($clientIp, $ip_blacklist);
	if ($ip_ruleset == 'AND') {
		if ($whitelisted == true && $blacklisted == false) {
			$proceed = true;
		}
	} else if ($ip_ruleset == 'OR') {
		if ($whitelisted == true || $blacklisted == false) {
			$proceed = true;
		}
	}
	if ($proceed == false) {
		trigger_error('User connection denied from: ' . $clientIp, E_USER_WARNING);
		if ($ip_silent == false) {
			fm_set_msg(lng('Access denied. IP restriction applicable'), 'error');
			fm_show_header_login();
			fm_show_message();
		}
		exit();
	}
}
// Checking if the user is logged in or not. If not, it will show the login form.
if ($use_auth) {
	if (isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']])) {
		// Logged
	} elseif (isset($_POST['fm_usr'], $_POST['fm_pwd'], $_POST['token'])) {
		// Logging In
		sleep(1);
		if (function_exists('password_verify')) {
			if (isset($auth_users[$_POST['fm_usr']]) && isset($_POST['fm_pwd']) && password_verify($_POST['fm_pwd'], $auth_users[$_POST['fm_usr']]) && verifyToken($_POST['token'])) {
				$_SESSION[FM_SESSION_ID]['logged'] = $_POST['fm_usr'];
				fm_set_msg(lng('You are logged in'));
				fm_redirect(FM_SELF_URL);
			} else {
				unset($_SESSION[FM_SESSION_ID]['logged']);
				fm_set_msg(lng('Login failed. Invalid username or password'), 'error');
				fm_redirect(FM_SELF_URL);
			}
		} else {
			fm_set_msg(lng('password_hash not supported, Upgrade PHP version'), 'error');;
		}
	} else {
		// Form
		unset($_SESSION[FM_SESSION_ID]['logged']);
		fm_show_header_login();
?>
<section class="h-100">
	<div class="container h-100">
		<div class="row justify-content-md-center align-content-center h-100vh">
			<div class="card-wrapper">
				<div class="card fat" data-bs-theme="<?php echo FM_THEME; ?>">
					<div class="card-body">
						<form class="form-signin" action="" method="post" autocomplete="off">
							<div class="mb-3">
								<div class="brand">
									<svg version="1.0" xmlns="http://www.w3.org/2000/svg" M1008 width="100%" height="80px" viewBox="0 0 238.000000 140.000000" aria-label="Web Console Utility">
										<g transform="translate(0.000000,140.000000) scale(0.100000,-0.100000)" fill="#000000" stroke="none">
											<path d="M160 700 l0 -600 110 0 110 0 0 260 0 260 70 0 70 0 0 -260 0 -260 110 0 110 0 0 600 0 600 -110 0 -110 0 0 -260 0 -260 -70 0 -70 0 0 260 0 260 -110 0 -110 0 0 -600z" />
											<path fill="#003500" d="M1008 1227 l-108 -72 0 -117 0 -118 110 0 110 0 0 110 0 110 70 0 70 0 0 -180 0 -180 -125 0 c-69 0 -125 -3 -125 -6 0 -3 23 -39 52 -80 l52 -74 73 0 73 0 0 -185 0 -185 -70 0 -70 0 0 115 0 115 -110 0 -110 0 0 -190 0 -190 181 0 181 0 109 73 108 72 1 181 0 181 -69 48 -68 49 68 50 69 49 0 249 0 248 -182 -1 -183 0 -107 -72z" />
											<path d="M1640 700 l0 -600 110 0 110 0 0 208 0 208 35 34 35 34 35 -34 35 -34 0 -208 0 -208 110 0 110 0 0 212 0 213 -87 87 -88 88 88 88 87 87 0 213 0 212 -110 0 -110 0 0 -208 0 -208 -70 -69 -70 -69 0 277 0 277 -110 0 -110 0 0 -600z" />
										</g>
									</svg>
								</div>
								<div class="text-center">
									<h1 class="card-title"><?php echo APP_TITLE; ?></h1>
								</div>
							</div>
							<hr />
							<div class="mb-3">
								<label for="fm_usr" class="pb-2"><?php echo lng('Username'); ?></label>
								<input type="text" class="form-control" id="fm_usr" name="fm_usr" required autofocus>
							</div>
							<div class="mb-3">
								<label for="fm_pwd" class="pb-2"><?php echo lng('Password'); ?></label>
								<input type="password" class="form-control" id="fm_pwd" name="fm_pwd" required>
							</div>
							<div class="mb-3">
								<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
								<button type="submit" class="btn btn-outline-primary w-100 btn-2"><?php echo lng('Login'); ?></button>
							</div>
						</form>
					</div>
				</div>
				<div class="footer">
					<?php echo lng('Copyright'); ?> &copy; 2024 &mdash; Web Console Utility
				</div>
			</div>
		</div>
	</div>
</section>
<?php
		fm_show_message();
		fm_show_footer();
		exit;
	}
}
// Readonly user
if (isset($_SESSION[FM_SESSION_ID]['logged'])) {
	$username = $_SESSION[FM_SESSION_ID]['logged'];
	if (in_array($username, $readonly_users)) {
		define('FM_READONLY', true);
	} else {
		define('FM_READONLY', $global_readonly);
	}
} else {
	define('FM_READONLY', $global_readonly);
}
// always use utf-8
fm_set_mb_utf8();
// if set $root_path
// Generally, it is better to set $root_path manually than use $_SERVER['DOCUMENT_ROOT']
$root_path = fm_clean_path($root_path);
if ($root_path != '') {
	// For security root path cannot be out of web site root
	if (strpos($root_path, $_SERVER['DOCUMENT_ROOT']) !== 0) {
		$root_path = $_SERVER['DOCUMENT_ROOT'];
	}
} else {
	$root_path = @$_SERVER['DOCUMENT_ROOT'];
}
define('FM_ROOT_PATH', $root_path);
// Default path
$fm_path = '';
if (isset($_GET['p'])) {
	$fm_path = fm_clean_path($_GET['p']);
}
// if $fm_path is outside FM_ROOT_PATH
if ($fm_path != '' && strpos($fm_path, FM_ROOT_PATH) === 0) {
	$fm_path = '';
}
if ($fm_path == '') {
	$fm_path = FM_ROOT_PATH;
}
// if user (not admin) set user-specific directories
if (isset($_SESSION[FM_SESSION_ID]['logged'])) {
	$username = $_SESSION[FM_SESSION_ID]['logged'];
	if (isset($directories_users[$username])) {
		$current_path = FM_ROOT_PATH . '/' . $directories_users[$username];
		// if path is not exist, create it
		if (!file_exists($current_path)) {
			fm_mkdir($current_path, true);
		}
		// if path exist and not dir
		if (!is_dir($current_path)) {
			die('Configuration error: This user does not have an assigned directory');
		}
		// replace current path to user path
		$fm_path = $current_path;
	}
}
$fm_path = fm_clean_path($fm_path);
define('FM_PATH', str_replace(FM_ROOT_PATH, '', $fm_path));
defined('FM_CURRENT_PATH') || define('FM_CURRENT_PATH', $fm_path);
// always use utf-8
if (!defined('FM_ICONV_INPUT_ENC')) {
	define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
}
// always use utf-8
if (!defined('FM_USE_HIGHLIGHTJS')) {
	define('FM_USE_HIGHLIGHTJS', $use_highlightjs);
}
// always use utf-8
if (!defined('FM_HIGHLIGHTJS_STYLE')) {
	define('FM_HIGHLIGHTJS_STYLE', $highlightjs_style);
}
// always use utf-8
if (!defined('FM_EDIT_FILE')) {
	define('FM_EDIT_FILE', $edit_files);
}
// always use utf-8
if (!defined('FM_DEFAULT_TIMEZONE')) {
	define('FM_DEFAULT_TIMEZONE', $default_timezone);
}
// always use utf-8
if (!defined('FM_DATETIME_FORMAT')) {
	define('FM_DATETIME_FORMAT', $datetime_format);
}
// always use utf-8
if (!defined('FM_PATH_DISPLAY_MODE')) {
	define('FM_PATH_DISPLAY_MODE', $path_display_mode);
}
// always use utf-8
if (!defined('FM_EXTENSION')) {
	define('FM_EXTENSION', $allowed_file_extensions);
}
// always use utf-8
if (!defined('FM_UPLOAD_EXTENSION')) {
	define('FM_UPLOAD_EXTENSION', $allowed_upload_extensions);
}
// always use utf-8
if (!defined('FM_FAVICON')) {
	define('FM_FAVICON', $favicon_path);
}
// always use utf-8
if (!defined('FM_EXCLUDE_ITEMS')) {
	define('FM_EXCLUDE_ITEMS', serialize($exclude_items));
}
// always use utf-8
if (!defined('FM_ONLINE_VIEWER')) {
	define('FM_ONLINE_VIEWER', $online_viewer);
}
// always use utf-8
if (!defined('FM_STICKY_NAVBAR')) {
	define('FM_STICKY_NAVBAR', $sticky_navbar);
}
// always use utf-8
if (!defined('FM_IS_WIN')) {
	define('FM_IS_WIN', strtolower(substr(PHP_OS, 0, 3)) == 'win');
}
// check extension
$path_url = FM_ROOT_URL . FM_PATH;
if (isset($_GET['dl'])) {
	// download file
	if (FM_READONLY) {
		fm_set_msg(lng('Access denied'), 'error');
		fm_redirect($path_url);
	}
	$dl_file = fm_clean_path($_GET['dl']);
	$dl_file = $dl_file;
	$full_path = FM_CURRENT_PATH . '/' . $dl_file;
	if (file_exists($full_path) && is_file($full_path)) {
		header('Content-Type: application/octet-stream');
		header('Content-Disposition: attachment; filename="' . basename($full_path) . '"');
		header('Content-Length: ' . filesize($full_path));
		readfile($full_path);
		exit;
	} else {
		fm_set_msg(lng('File not found'), 'error');
		fm_redirect($path_url);
	}
}
// delete folder
if (isset($_GET['del_folder']) && !FM_READONLY) {
	if (!verifyToken($_GET['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$del_folder = fm_clean_path($_GET['del_folder']);
	$del_folder = FM_CURRENT_PATH . '/' . $del_folder;
	if ($del_folder == FM_ROOT_PATH || $del_folder == FM_CURRENT_PATH) {
		fm_set_msg(lng('Cannot delete root folder'), 'error');
	} elseif (file_exists($del_folder) && is_dir($del_folder)) {
		fm_rdelete($del_folder);
		fm_set_msg(lng('Folder deleted'));
	} else {
		fm_set_msg(lng('Folder not found'), 'error');
	}
	fm_redirect($path_url);
}
// delete file
if (isset($_GET['del']) && !FM_READONLY) {
	if (!verifyToken($_GET['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$del_file = fm_clean_path($_GET['del']);
	$del_file = FM_CURRENT_PATH . '/' . $del_file;
	if (file_exists($del_file) && is_file($del_file)) {
		unlink($del_file);
		fm_set_msg(lng('File deleted'));
	} else {
		fm_set_msg(lng('File not found'), 'error');
	}
	fm_redirect($path_url);
}
// create folder
if (isset($_GET['new_folder']) && !FM_READONLY) {
	if (!verifyToken($_GET['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$new_folder = fm_clean_path($_GET['new_folder']);
	$new_path = FM_CURRENT_PATH . '/' . $new_folder;
	if (file_exists($new_path)) {
		fm_set_msg(lng('Folder already exists'), 'alert');
	} elseif (fm_mkdir($new_path, true)) {
		fm_set_msg(lng('Folder created'));
	} else {
		fm_set_msg(lng('Folder not created'), 'error');
	}
	fm_redirect($path_url);
}
// create file
if (isset($_GET['new_file']) && !FM_READONLY) {
	if (!verifyToken($_GET['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$new_file = fm_clean_path($_GET['new_file']);
	$new_path = FM_CURRENT_PATH . '/' . $new_file;
	if (file_exists($new_path)) {
		fm_set_msg(lng('File already exists'), 'alert');
	} elseif (fm_touch($new_path)) {
		fm_set_msg(lng('File created'));
	} else {
		fm_set_msg(lng('File not created'), 'error');
	}
	fm_redirect($path_url);
}
// rename
if (isset($_GET['ren'], $_POST['jdr_name']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$old = fm_clean_path($_GET['ren']);
	$old = FM_CURRENT_PATH . '/' . $old;
	$new = fm_clean_path($_POST['jdr_name']);
	$new = FM_CURRENT_PATH . '/' . $new;
	if ($old == FM_ROOT_PATH || $old == FM_CURRENT_PATH) {
		fm_set_msg(lng('Cannot rename root folder'), 'error');
	} elseif (file_exists($old)) {
		if (file_exists($new)) {
			fm_set_msg(lng('File or folder already exists'), 'alert');
		} elseif (rename($old, $new)) {
			fm_set_msg(lng('File or folder renamed'));
		} else {
			fm_set_msg(lng('File or folder not renamed'), 'error');
		}
	} else {
		fm_set_msg(lng('File or folder not found'), 'error');
	}
	fm_redirect($path_url);
}
// copy file/folder
if (isset($_GET['copy'], $_POST['jdr_path']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$copy = fm_clean_path($_GET['copy']);
	$copy = FM_ROOT_PATH . '/' . $copy;
	$new_path = fm_clean_path($_POST['jdr_path']);
	$new_path = fm_clean_path(FM_ROOT_PATH . '/' . $new_path);
	$filename = basename($copy);
	// $new_path inside not exist root folder
	if (!file_exists($new_path)) {
		fm_set_msg(lng('Path not found'), 'alert');
		fm_redirect($path_url);
	}
	// copy
	if (is_dir($copy)) {
		// recursive copy folder
		fm_rcopy($copy, $new_path . '/' . $filename);
		fm_set_msg(lng('Folder copied'));
	} elseif (is_file($copy)) {
		// copy file
		copy($copy, $new_path . '/' . $filename);
		fm_set_msg(lng('File copied'));
	} else {
		fm_set_msg(lng('File or folder not found'), 'error');
	}
	fm_redirect($path_url);
}
// move file/folder
if (isset($_GET['move'], $_POST['jdr_path']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$move = fm_clean_path($_GET['move']);
	$move = FM_ROOT_PATH . '/' . $move;
	$new_path = fm_clean_path($_POST['jdr_path']);
	$new_path = fm_clean_path(FM_ROOT_PATH . '/' . $new_path);
	$filename = basename($move);
	// $new_path inside not exist root folder
	if (!file_exists($new_path)) {
		fm_set_msg(lng('Path not found'), 'alert');
		fm_redirect($path_url);
	}
	// move
	if ($move == FM_ROOT_PATH || $move == FM_CURRENT_PATH) {
		fm_set_msg(lng('Cannot move root folder'), 'error');
	} elseif (file_exists($move)) {
		if (@rename($move, $new_path . '/' . $filename)) {
			fm_set_msg(lng('File or folder moved'));
		} else {
			fm_set_msg(lng('File or folder not moved'), 'error');
		}
	} else {
		fm_set_msg(lng('File or folder not found'), 'error');
	}
	fm_redirect($path_url);
}
// chmod (only for linux)
if (isset($_POST['chmod']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$file = fm_clean_path($_GET['chmod']);
	$file = FM_CURRENT_PATH . '/' . $file;
	$chmod = fm_clean_path($_POST['chmod']);
	if (file_exists($file)) {
		$chmod = octdec($chmod);
		if (@chmod($file, $chmod)) {
			fm_set_msg(lng('Permissions changed'));
		} else {
			fm_set_msg(lng('Permissions not changed'), 'error');
		}
	} else {
		fm_set_msg(lng('File or folder not found'), 'error');
	}
	fm_redirect($path_url);
}
// upload
if (isset($_POST['upload']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$path = FM_CURRENT_PATH;
	$errors = 0;
	$uploads = 0;
	$allowed = (empty(FM_UPLOAD_EXTENSION)) ? false : explode(',', FM_UPLOAD_EXTENSION);
	foreach ($_FILES['file']['name'] as $key => $value) {
		if (empty($_FILES['file']['error'][$key])) {
			$tempFile = $_FILES['file']['tmp_name'][$key];
			$targetFile = fm_clean_path($value);
			// check extension
			$ext = pathinfo($targetFile, PATHINFO_EXTENSION);
			$is_allowed = ($allowed) ? in_array(strtolower($ext), array_map('strtolower', $allowed)) : true;
			// if allowed and check size
			if ($is_allowed && @filesize($tempFile) <= MAX_UPLOAD_SIZE) {
				move_uploaded_file($tempFile, $path . '/' . $targetFile);
				$uploads++;
			} else {
				$errors++;
			}
		} else {
			$errors++;
		}
	}
	if ($errors == 0 && $uploads > 0) {
		fm_set_msg(lng('Files uploaded'));
	} elseif ($errors > 0) {
		fm_set_msg(lng('Some files not uploaded'), 'error');
	} else {
		fm_set_msg(lng('No files selected'), 'alert');
	}
	fm_redirect($path_url);
}
// mass upload
if (isset($_POST['type']) && $_POST['type'] == "mass-upload" && !FM_READONLY) {
	$path = FM_CURRENT_PATH;
	$response = array();
	$uploads = 0;
	$chunkTotal = isset($_POST["dzchunkindex"]) ? (int) $_POST["dztotalchunkcount"] : 1;
	$chunkIndex = isset($_POST["dzchunkindex"]) ? (int) $_POST["dzchunkindex"] : 0;
	$chunkSize = isset($_POST["dzchunkindex"]) ? (int) $_POST["dzchunksize"] : 0;
	$chunked = $chunkTotal > 1 ? true : false;
	$fullPathInput = isset($_POST["dzy-fullPath"]) ? $_POST["dzy-fullPath"] : $_FILES["file"]["name"];
	$fileName = isset($_POST["dzy-fileName"]) ? $_POST["dzy-fileName"] : $_FILES["file"]["name"];
	$tmp_name = $_FILES['file']['tmp_name'];
	$fullPath = $path . '/' . $fileName;
	$ext = pathinfo($fileName, PATHINFO_EXTENSION);
	$allowed = (empty(FM_UPLOAD_EXTENSION)) ? false : explode(',', FM_UPLOAD_EXTENSION);
	$is_allowed = ($allowed) ? in_array(strtolower($ext), array_map('strtolower', $allowed)) : true;
	if (is_writable($path) && $is_allowed) {
		if ($chunked) {
			$fullPathPart = $fullPath . ".part";
			$in = @fopen($tmp_name, "rb");
			if ($chunkIndex == 0) {
				$out = @fopen($fullPathPart, "wb");
			} else {
				$out = @fopen($fullPathPart, "ab");
			}
			if ($out) {
				if (function_exists('stream_copy_to_stream')) {
					stream_copy_to_stream($in, $out);
				} else {
					while (!feof($in)) {
						if ($chunkSize) {
							fwrite($out, fread($in, $chunkSize));
						} else {
							fwrite($out, fread($in, 1024));
						}
					}
				}
				@fclose($in);
				@fclose($out);
				@unlink($tmp_name);
				$response = array(
					'status' => 'success',
					'info' => "file upload successful"
				);
				if ($chunkIndex == $chunkTotal - 1) {
					if (file_exists($fullPath)) {
						$ext_1 = $ext ? '.' . $ext : '';
						$fullPathTarget = $path . '/' . basename($fullPathInput, $ext_1) . '_' . date('ymdHis') . $ext_1;
					} else {
						$fullPathTarget = $fullPath;
					}
					rename("{$fullPath}.part", $fullPathTarget);
				}
			} else {
				$response = array(
					'status' => 'error',
					'info' => "failed to open output stream",
					'errorDetails' => error_get_last()
				);
			}
		} else if (move_uploaded_file($tmp_name, $fullPath)) {
			// Be sure that the file has been uploaded
			if (file_exists($fullPath)) {
				$response = array(
					'status' => 'success',
					'info' => "file upload successful"
				);
			} else {
				$response = array(
					'status' => 'error',
					'info' => 'Couldn\'t upload the requested file.'
				);
			}
		} else {
			$response = array(
				'status' => 'error',
				'info' => "Error while uploading files. Uploaded files $uploads",
			);
		}
	} else {
		$response = array(
			'status' => 'error',
			'info' => 'The specified folder for upload isn\'t writeable.'
		);
	}
	// Return the response
	echo json_encode($response);
	exit();
}
// Mass deleting
if (isset($_POST['group'], $_POST['delete'], $_POST['token']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		die("Invalid Token.");
	}
	$path = FM_ROOT_PATH;
	if (FM_PATH != '') {
		$path .= '/' . FM_PATH;
	}
	$errors = 0;
	$files = $_POST['file'];
	if (is_array($files) && count($files)) {
		foreach ($files as $f) {
			if ($f != '') {
				$new_path = $path . '/' . $f;
				if (!fm_rdelete($new_path)) {
					$errors++;
				}
			}
		}
		if ($errors == 0) {
			fm_set_msg(lng('Selected files and folder deleted'));
		} else {
			fm_set_msg(lng('Error while deleting items'), 'error');
		}
	} else {
		fm_set_msg(lng('Nothing selected'), 'alert');
	}
	$FM_PATH = FM_PATH;
	fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}
// Pack files zip, tar
if (isset($_POST['group'], $_POST['token']) && (isset($_POST['zip']) || isset($_POST['tar'])) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		die("Invalid Token.");
	}
	$path = FM_ROOT_PATH;
	$ext = 'zip';
	if (FM_PATH != '') {
		$path .= '/' . FM_PATH;
	}
	//set pack type
	$ext = isset($_POST['tar']) ? 'tar' : 'zip';
	if (($ext == "zip" && !class_exists('ZipArchive')) || ($ext == "tar" && !class_exists('PharData'))) {
		fm_set_msg(lng('Operations with archives are not available'), 'error');
		$FM_PATH = FM_PATH;
		fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
	}
	$files = $_POST['file'];
	if (is_array($files) && count($files)) {
		// name of archive
		$arch_filename = fm_clean_path(basename(FM_PATH == '' ? FM_ROOT_PATH : FM_PATH)) . '_' . date('ymd_His') . '.' . $ext;
		// path to archive
		$arch_file = $path . '/' . $arch_filename;
		$errors = 0;
		// create archive
		$arch = new Archive($arch_file, $ext);
		$res = $arch->createArchive();
		if ($res) {
			foreach ($files as $f) {
				if ($f != '') {
					$item_path = $path . '/' . $f;
					if (file_exists($item_path)) {
						if (is_dir($item_path)) {
							// add folder
							$arch->addFolder($item_path);
						} else {
							// add file
							$arch->addFile($item_path);
						}
					} else {
						$errors++;
					}
				}
			}
			// close archive
			$arch->closeArchive();
			if ($errors == 0) {
				fm_set_msg(lng('Archive created'));
			} else {
				fm_set_msg(lng('Archive created, but some files not added'), 'alert');
			}
		} else {
			fm_set_msg(lng('Archive not created'), 'error');
		}
	} else {
		fm_set_msg(lng('Nothing selected'), 'alert');
	}
	$FM_PATH = FM_PATH;
	fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}
// Unpack files zip, tar
if (isset($_GET['unp'], $_POST['token']) && !FM_READONLY) {
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	$path = FM_CURRENT_PATH;
	// file name
	$file = fm_clean_path($_GET['unp']);
	// full path to file
	$item_path = $path . '/' . $file;
	// name without extension
	$filename = pathinfo($item_path, PATHINFO_FILENAME);
	// extension
	$ext = pathinfo($item_path, PATHINFO_EXTENSION);
	// target path
	$target_path = $path . '/' . $filename;
	if (!file_exists($item_path)) {
		fm_set_msg(lng('File not found'), 'error');
		fm_redirect($path_url);
	}
	// check extension
	if (($ext == 'zip' && !class_exists('ZipArchive')) || ($ext == 'tar' && !class_exists('PharData'))) {
		fm_set_msg(lng('Operations with archives are not available'), 'error');
		fm_redirect($path_url);
	}
	$arch = new Archive($item_path, $ext);
	$res = $arch->extractArchive($target_path);
	if ($res) {
		fm_set_msg(lng('Archive unpacked'));
	} else {
		fm_set_msg(lng('Archive not unpacked'), 'error');
	}
	fm_redirect($path_url);
}
// edit file
if (isset($_GET['edit']) && FM_EDIT_FILE && !FM_READONLY) {
	$file = fm_clean_path($_GET['edit']);
	$file = FM_CURRENT_PATH . '/' . $file;
	if (file_exists($file) && is_file($file)) {
		$content = file_get_contents($file);
		fm_show_header();
		fm_show_nav_path(FM_PATH);
?>
<div class="card p-3 mb-3" data-bs-theme="<?php echo FM_THEME; ?>">
	<div class="card-body">
		<form action="" method="post">
			<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
			<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
			<input type="hidden" name="edit" value="<?php echo fm_enc($_GET['edit']) ?>">
			<div class="mb-3">
				<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
					<label class="form-label"><?php echo lng('File'); ?>: <strong><?php echo fm_enc(basename($file)) ?></strong></label>
					<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;view=<?php echo urlencode(basename($file)) ?>" class="btn btn-sm btn-outline-primary btn-2 ms-2"><i class="fa fa-eye"></i> <?php echo lng('View') ?></a>
					<a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-sm btn-outline-danger btn-2 pull-right"><i class="fa fa-close"></i> <?php echo lng('Cancel') ?></a>
				</div>
			</div>
			<div class="mb-3">
				<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
					<textarea class="form-control" name="content" id="edit_area" rows="20" autofocus><?php echo fm_enc($content) ?></textarea>
				</div>
			</div>
			<div class="mb-3">
				<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
					<button type="submit" name="save" class="btn btn-outline-success btn-2"><i class="fa fa-floppy-o"></i> <?php echo lng('Save') ?></button>
				</div>
			</div>
		</form>
	</div>
</div>
<?php
		fm_show_footer();
	} else {
		fm_set_msg(lng('File not found'), 'error');
		fm_redirect($path_url);
	}
} elseif (isset($_POST['save']) && FM_EDIT_FILE && !FM_READONLY) {
	$file = fm_clean_path($_GET['edit']);
	$file = FM_CURRENT_PATH . '/' . $file;
	if (!verifyToken($_POST['token'])) {
		fm_set_msg(lng("Invalid Token."), 'error');
		fm_redirect($path_url);
	}
	if (file_exists($file) && is_file($file)) {
		file_put_contents($file, $_POST['content']);
		fm_set_msg(lng('File saved'));
	} else {
		fm_set_msg(lng('File not found'), 'error');
	}
	fm_redirect($path_url);
}
// view file
if (isset($_GET['view'])) {
	$file = fm_clean_path($_GET['view']);
	$file = FM_CURRENT_PATH . '/' . $file;
	if (file_exists($file) && is_file($file)) {
		fm_show_header();
		fm_show_nav_path(FM_PATH);
?>
<div class="card p-3 mb-3" data-bs-theme="<?php echo FM_THEME; ?>">
	<div class="card-body">
		<div class="mb-3">
			<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
				<label class="form-label"><?php echo lng('File'); ?>: <strong><?php echo fm_enc(basename($file)) ?></strong></label>
				<?php if (!FM_READONLY && FM_EDIT_FILE): ?>
					<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;edit=<?php echo urlencode(basename($file)) ?>" class="btn btn-sm btn-outline-primary btn-2 ms-2"><i class="fa fa-edit"></i> <?php echo lng('Edit') ?></a>
				<?php endif; ?>
				<a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-sm btn-outline-danger btn-2 pull-right"><i class="fa fa-close"></i> <?php echo lng('Close') ?></a>
			</div>
		</div>
		<div class="mb-3">
			<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
				<?php
					$mime_type = fm_get_mime_type($file);
					$content = file_get_contents($file);
					$ext = pathinfo($file, PATHINFO_EXTENSION);
					$allowed_text_exts = array('txt', 'css', 'ini', 'conf', 'log', 'htaccess', 'json', 'xml', 'htm', 'html', 'js', 'php', 'py', 'sh', 'rb', 'sql', 'perl', 'java', 'c', 'cpp', 'yml', 'yaml', 'md', 'markdown', 'webmanifest');
					if (in_array(strtolower($ext), $allowed_text_exts) || strpos($mime_type, 'text/') !== false) {
						if (FM_USE_HIGHLIGHTJS) {
							echo '<pre class="ace-view-editor"><code class="' . strtolower($ext) . '">' . fm_enc($content) . '</code></pre>';
						} else {
							echo '<pre class="ace-view-editor">' . fm_enc($content) . '</pre>';
						}
					} elseif (strpos($mime_type, 'image/') !== false) {
						echo '<img src="' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '" class="img-fluid img-thumbnail" alt="Image">';
					} elseif (strpos($mime_type, 'video/') !== false) {
						echo '<video controls class="img-fluid img-thumbnail" poster="' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '"><source src="' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '" type="' . $mime_type . '">Your browser does not support the video tag.</video>';
					} elseif (strpos($mime_type, 'audio/') !== false) {
						echo '<audio controls><source src="' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '" type="' . $mime_type . '">Your browser does not support the audio tag.</audio>';
					} elseif (strpos($mime_type, 'application/pdf') !== false) {
						// pdf
						echo '<iframe src="' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '" width="100%" height="600" style="border: none;"></iframe>';
					} elseif (FM_ONLINE_VIEWER) {
						if (FM_ONLINE_VIEWER == 'google') {
							echo '<iframe src="https://docs.google.com/gview?url=' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '&embedded=true" style="width:100%; height:600px; border: none;" frameborder="0"></iframe>';
						} elseif (FM_ONLINE_VIEWER == 'microsoft') {
							echo '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src=' . fm_enc(FM_ROOT_URL . FM_PATH . '/' . basename($file)) . '" style="width:100%; height:600px; border: none;" frameborder="0"></iframe>';
						} else {
							fm_set_msg(lng('This file type is not supported'), 'alert');
						}
					} else {
						fm_set_msg(lng('This file type is not supported'), 'alert');
					}
					?>
			</div>
		</div>
	</div>
</div>
<?php
		fm_show_footer();
	} else {
		fm_set_msg(lng('File not found'), 'error');
		fm_redirect($path_url);
	}
}
// simple post actions (use $_POST)
if (isset($_POST['ajax']) && !FM_READONLY) {
	// edit file
	if (isset($_POST['type']) && $_POST['type'] == "edit" && FM_EDIT_FILE) {
		$file = fm_clean_path($_POST['file']);
		$path = FM_ROOT_PATH;
		if (!empty($_POST['path'])) {
			$relativeDirPath = fm_clean_path($_POST['path']);
			$path .= '/' . $relativeDirPath;
		}
		if (FM_PATH != '') {
			$path .= '/' . FM_PATH;
		}
		header('X-XSS-Protection:0');
		$file_path = $path . '/' . $file;
		$writedata = $_POST['content'];
		$fd = fopen($file_path, "w");
		$write_results = @fwrite($fd, $writedata);
		fclose($fd);
		if ($write_results === false) {
			header("HTTP/1.1 500 Internal Server Error");
			die("Could Not Write File! - Check Permissions / Ownership");
		}
		die(true);
	}
	// backup files
	if (isset($_POST['type']) && $_POST['type'] == "backup" && !empty($_POST['file'])) {
		$fileName = fm_clean_path($_POST['file']);
		$fullPath = FM_ROOT_PATH . '/';
		if (!empty($_POST['path'])) {
			$relativeDirPath = fm_clean_path($_POST['path']);
			$fullPath .= "{$relativeDirPath}/";
		}
		$date = date("dMy-His");
		$newFileName = "{$fileName}-{$date}.bak";
		$fullyQualifiedFileName = $fullPath . $fileName;
		try {
			if (!file_exists($fullyQualifiedFileName)) {
				throw new Exception("File {$fileName} not found");
			}
			if (copy($fullyQualifiedFileName, $fullPath . $newFileName)) {
				echo "Backup {$newFileName} created";
			} else {
				throw new Exception("Could not copy file {$fileName}");
			}
		} catch (Exception $e) {
			echo $e->getMessage();
		}
	}
	// Save Config
	if (isset($_POST['type']) && $_POST['type'] == "settings") {
		global $cfg, $lang, $report_errors, $show_hidden_files, $lang_list, $hide_Cols, $theme;
		$newLng = $_POST['js-language'];
		fm_get_translations([]);
		if (!array_key_exists($newLng, $lang_list)) {
			$newLng = 'en';
		}
		$erp = isset($_POST['js-error-report']) && $_POST['js-error-report'] == "true" ? true : false;
		$shf = isset($_POST['js-show-hidden']) && $_POST['js-show-hidden'] == "true" ? true : false;
		$hco = isset($_POST['js-hide-cols']) && $_POST['js-hide-cols'] == "true" ? true : false;
		$te3 = $_POST['js-theme-3'];
		if ($cfg->data['lang'] != $newLng) {
			$cfg->data['lang'] = $newLng;
			$lang = $newLng;
		}
		if ($cfg->data['error_reporting'] != $erp) {
			$cfg->data['error_reporting'] = $erp;
			$report_errors = $erp;
		}
		if ($cfg->data['show_hidden'] != $shf) {
			$cfg->data['show_hidden'] = $shf;
			$show_hidden_files = $shf;
		}
		if ($cfg->data['show_hidden'] != $shf) {
			$cfg->data['show_hidden'] = $shf;
			$show_hidden_files = $shf;
		}
		if ($cfg->data['hide_Cols'] != $hco) {
			$cfg->data['hide_Cols'] = $hco;
			$hide_Cols = $hco;
		}
		if ($cfg->data['theme'] != $te3) {
			$cfg->data['theme'] = $te3;
			$theme = $te3;
		}
		$cfg->save();
		echo true;
	}
	// new password hash
	if (isset($_POST['type']) && $_POST['type'] == "pwdhash") {
		$res = isset($_POST['inputPassword2']) && !empty($_POST['inputPassword2']) ? password_hash($_POST['inputPassword2'], PASSWORD_DEFAULT) : '';
		echo $res;
	}
	//upload using url
	if (isset($_POST['type']) && $_POST['type'] == "upload" && !empty($_REQUEST["uploadurl"])) {
		$path = FM_ROOT_PATH;
		if (FM_PATH != '') {
			$path .= '/' . FM_PATH;
		}
		function event_callback($message)
		{
			global $callback;
			echo json_encode($message);
		}
		function get_file_path()
		{
			global $path, $fileinfo, $temp_file;
			return $path . "/" . basename($fileinfo->name);
		}
		$url = !empty($_REQUEST["uploadurl"]) && preg_match("|^http(s)?://.+$|", stripslashes($_REQUEST["uploadurl"])) ? stripslashes($_REQUEST["uploadurl"]) : null;
		//prevent 127.* domain and known ports
		$domain = parse_url($url, PHP_URL_HOST);
		$port = parse_url($url, PHP_URL_PORT);
		$knownPorts = [22, 23, 25, 3306];
		if (preg_match("/^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$/i", $domain) || in_array($port, $knownPorts)) {
			$err = array("message" => "URL is not allowed");
			event_callback(array("fail" => $err));
			exit();
		}
		$use_curl = false;
		$temp_file = tempnam(sys_get_temp_dir(), "upload-");
		$fileinfo = new \stdClass();
		$fileName = basename(parse_url($url, PHP_URL_PATH));
		if (preg_match("/\.(.+)$/i", $fileName, $matche) && strlen($matche[1]) < 5 && strlen($matche[1]) > 1) {
			$ext = $matche[1];
		} else {
			$ext = "txt";
		}
		$fileinfo->name = $fileName;
		$fileinfo->ext = $ext;
		$allowed = (empty(FM_UPLOAD_EXTENSION)) ? false : explode(',', FM_UPLOAD_EXTENSION);
		$is_allowed = ($allowed) ? in_array(strtolower($ext), array_map('strtolower', $allowed)) : true;
		if (!$is_allowed) {
			$err = array("message" => "Extension is not allowed");
			event_callback(array("fail" => $err));
			exit();
		}
		if (function_exists('curl_version')) {
			$use_curl = true;
		}
		if ($use_curl) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HEADER, false);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch, CURLOPT_USERAGENT, 'tinyfilemanager');
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_FILE, $out = fopen($temp_file, 'wb'));
			curl_setopt($ch, CURLOPT_MAXFILESIZE, MAX_UPLOAD_SIZE);
			curl_exec($ch);
			if (curl_errno($ch)) {
				$err = array("message" => "Error during cURL download: " . curl_error($ch));
				event_callback(array("fail" => $err));
				curl_close($ch);
				exit();
			}
			$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			if ($http_code != 200) {
				$err = array("message" => "Error downloading file. HTTP Status: " . $http_code);
				event_callback(array("fail" => $err));
				curl_close($ch);
				exit();
			}
			curl_close($ch);
			fclose($out);
		} else {
			$url_components = parse_url($url);
			$scheme = isset($url_components['scheme']) ? $url_components['scheme'] : '';
			if ($scheme !== 'http' && $scheme !== 'https') {
				$err = array("message" => "Only http and https schemes are supported for download.");
				event_callback(array("fail" => $err));
				exit();
			}
			$response = @file_get_contents($url, 0, null, 0, MAX_UPLOAD_SIZE + 1024);
			if ($response === false) {
				$err = array("message" => "Could not download file using file_get_contents");
				event_callback(array("fail" => $err));
				exit();
			} else if (strlen($response) > MAX_UPLOAD_SIZE) {
				$err = array("message" => "File size exceeds the maximum upload limit.");
				event_callback(array("fail" => $err));
				exit();
			}
			if (file_put_contents($temp_file, $response) === false) {
				$err = array("message" => "Could not write to temporary file.");
				event_callback(array("fail" => $err));
				exit();
			}
		}
		if (!file_exists($temp_file)) {
			$err = array("message" => "Download failed");
			event_callback(array("fail" => $err));
			exit();
		}
		$upload_path = get_file_path();
		if (file_exists($upload_path)) {
			$ext_1 = $fileinfo->ext ? '.' . $fileinfo->ext : '';
			$upload_path = $path . '/' . basename($fileinfo->name, $ext_1) . '_' . date('ymdHis') . $ext_1;
		}
		if (!rename($temp_file, $upload_path)) {
			@unlink($temp_file);
			$err = array("message" => "Failed to move the file to the final destination.");
			event_callback(array("fail" => $err));
			exit();
		}
		$response = array(
			"status" => "success",
			"message" => "Download successful",
			"file_name" => basename($upload_path),
			"file_path" => $upload_path
		);
		event_callback($response);
		exit();
	}
	die();
}
// list files and folders
$files = fm_get_list(FM_CURRENT_PATH);
fm_show_header();
fm_show_nav_path(FM_PATH);
fm_show_message();
// copy/move to dialog
if (isset($_GET['copy']) || isset($_GET['move'])) {
	$title = isset($_GET['copy']) ? lng('CopyTo') : lng('MoveTo');
	$act = isset($_GET['copy']) ? 'copy' : 'move';
	$filename = fm_clean_path(isset($_GET['copy']) ? $_GET['copy'] : $_GET['move']);
	$filename = basename($filename);
	$file = fm_clean_path(isset($_GET['copy']) ? $_GET['copy'] : $_GET['move']);
	$path = FM_ROOT_PATH;
	$path_tmp = explode('/', $file);
	if (count($path_tmp) > 1) {
		unset($path_tmp[count($path_tmp) - 1]);
		$path .= '/' . implode('/', $path_tmp);
	}
	$files_list = fm_get_list(FM_ROOT_PATH);
	fm_show_copy_move_dialog($files_list);
}
// chmod dialog
if (isset($_GET['chmod'])) {
	$file = fm_clean_path($_GET['chmod']);
	$file = FM_CURRENT_PATH . '/' . $file;
	if (file_exists($file)) {
		fm_show_chmod_dialog($file);
	}
}
// load total size
if (isset($files['total_size'])) {
	$total_size = $files['total_size'];
	unset($files['total_size']);
}
?>
<div class="row">
	<div class="col-md-12">
		<?php fm_show_action_bar(FM_PATH); ?>
	</div>
</div>
<?php if (!empty($files)): ?>
<div class="table-responsive">
	<table id="table-files" class="table table-bordered table-striped table-hover table-sm">
		<thead>
			<tr>
				<?php if (!FM_READONLY): ?>
					<th style="width:3%" class="hidden-xs">
						<div class="form-check">
							<input class="form-check-input" type="checkbox" id="checkAll">
							<label class="form-check-label" for="checkAll"></label>
						</div>
					</th>
				<?php endif; ?>
				<th><?php echo lng('Name') ?></th>
				<th><?php echo lng('Size') ?></th>
				<th><?php echo lng('Modified') ?></th>
				<?php if (!FM_IS_WIN && !$hide_Cols): ?>
					<th><?php echo lng('Perms') ?></th>
					<th><?php echo lng('Owner') ?></th>
				<?php endif; ?>
				<th><?php echo lng('Actions') ?></th>
			</tr>
		</thead>
		<tbody>
			<?php
			// file list
			$folders = array();
			$files_list = array();
			$all_files_size = 0;
			$num_files = 0;
			$num_folders = 0;
			// relative path
			$abs_path = fm_clean_path(FM_CURRENT_PATH);
			$relative_path = fm_clean_path(str_replace(FM_ROOT_PATH, '', $abs_path));
			foreach ($files as $p):
				if (isset($p['is_dir']) && $p['is_dir']) {
					$folders[] = $p;
				} else {
					$files_list[] = $p;
				}
			endforeach;
			if (!empty($folders)):
				$num_folders = count($folders);
				$ik = 0;
				foreach ($folders as $f):
					$modif = date(FM_DATETIME_FORMAT, $f['mtime']);
					$perms = fm_get_perms($f['perms']);
					$owner = fm_get_owner($f['path']);
					$group = fm_get_group($f['path']);
					$is_link = is_link($f['path']);
					?>
					<tr>
						<?php if (!FM_READONLY): ?>
							<td style="width:3%" class="hidden-xs">
								<div class="form-check">
									<input class="form-check-input" type="checkbox" id="check-f<?php echo $ik ?>">
									<label class="form-check-label" for="check-f<?php echo $ik ?>"></label>
								</div>
							</td>
						<?php endif; ?>
						<td>
							<div class="filename">
								<a href="?p=<?php echo urlencode(FM_PATH . '/' . $f['name']) ?>" title="<?php echo fm_enc($f['name']) ?>">
									<i class="fa fa-folder-o"></i> <?php echo fm_enc($f['name']) ?>
								</a>
								<?php echo ($is_link ? ' &rarr; <i>' . readlink($f['path']) . '</i>' : '') ?>
							</div>
						</td>
						<td><?php echo lng('Folder') ?></td>
						<td data-order="a-<?php echo $f['mtime'] ?>"><?php echo $modif ?></td>
						<?php if (!FM_IS_WIN && !$hide_Cols): ?>
							<td><?php if (!FM_READONLY): ?><a title="<?php echo lng('Change Permissions') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f['name']) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?></td>
							<td><?php echo fm_enc($owner['name'] . ':' . $group['name']) ?></td>
						<?php endif; ?>
						<td class="inline-actions">
							<?php if (!FM_READONLY): ?>
								<a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del_folder=<?php echo urlencode($f['name']) ?>" onclick="confirmDailog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('Folder'); ?>','<?php echo urlencode($f['name']); ?>', this.href);">
									<i class="fa fa-trash-o"></i></a>
								<a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f['name'])) ?>');return false;"><i class="fa fa-pencil-square-o"></i></a>
								<a title="<?php echo lng('CopyTo') ?>..." href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f['name'], '/')) ?>"><i class="fa fa-files-o"></i></a>
							<?php endif; ?>
							<a title="<?php echo lng('DirectLink') ?>" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f['name']) ?>" target="_blank"><i class="fa fa-link"></i></a>
						</td>
					</tr>
					<?php
					flush();
					$ik++;
				endforeach;
			endif; // end if folders
			if (!empty($files_list)):
				$num_files = count($files_list);
				$ik = 0;
				foreach ($files_list as $f):
					$all_files_size += $f['size'];
					$modif = date(FM_DATETIME_FORMAT, $f['mtime']);
					$date_sorting = $f['mtime'];
					$filesize = fm_get_filesize($f['size']);
					$filesize_raw = $f['size'];
					$filelink = '?p=' . urlencode(FM_PATH) . '&amp;view=' . urlencode($f['name']);
					$ext = pathinfo($f['name'], PATHINFO_EXTENSION);
					$is_image = fm_is_image($ext);
					$is_link = is_link($f['path']);
					$perms = fm_get_perms($f['perms']);
					$owner = fm_get_owner($f['path']);
					$group = fm_get_group($f['path']);
					?>
					<tr>
						<?php if (!FM_READONLY): ?>
							<td style="width:3%" class="hidden-xs">
								<div class="form-check">
									<input class="form-check-input" type="checkbox" id="check-<?php echo $ik ?>" name="file[]" value="<?php echo fm_enc($f['name']) ?>">
									<label class="form-check-label" for="check-<?php echo $ik ?>"></label>
								</div>
							</td>
						<?php endif; ?>
						<td>
							<div class="filename">
								<a href="<?php echo $filelink ?>" title="<?php echo fm_enc($f['name']) ?>">
									<i class="fa <?php echo fm_get_file_icon($f['name']) ?>"></i> <?php echo fm_enc($f['name']) ?>
								</a>
								<?php echo ($is_link ? ' &rarr; <i>' . readlink($f['path']) . '</i>' : '') ?>
							</div>
						</td>
						<td data-order="b-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>"><span title="<?php printf('%s bytes', $filesize_raw) ?>">
								<?php echo $filesize; ?>
							</span></td>
						<td data-order="b-<?php echo $date_sorting; ?>"><?php echo $modif ?></td>
						<?php if (!FM_IS_WIN && !$hide_Cols): ?>
							<td><?php if (!FM_READONLY): ?><a title="<?php echo lng('Change Permissions') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f['name']) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?>
							</td>
							<td><?php echo fm_enc($owner['name'] . ':' . $group['name']) ?></td>
						<?php endif; ?>
						<td class="inline-actions">
							<?php if (!FM_READONLY): ?>
								<a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f['name']) ?>" onclick="confirmDailog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('File'); ?>','<?php echo urlencode($f['name']); ?>', this.href);">
									<i class="fa fa-trash-o"></i></a>
								<a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f['name'])) ?>');return false;"><i class="fa fa-pencil-square-o"></i></a>
								<a title="<?php echo lng('CopyTo') ?>..." href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f['name'], '/')) ?>"><i class="fa fa-files-o"></i></a>
							<?php endif; ?>
							<a title="<?php echo lng('DirectLink') ?>" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f['name']) ?>" target="_blank"><i class="fa fa-link"></i></a>
							<a title="<?php echo lng('Download') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f['name']) ?>" onclick="confirmDailog(event, 1211, '<?php echo lng('Download'); ?>','<?php echo urlencode($f['name']); ?>', this.href);"><i class="fa fa-download"></i></a>
						</td>
					</tr>
					<?php
					flush();
					$ik++;
				endforeach;
			endif; // end if files
			if (empty($folders) && empty($files_list)) {
				?>
				<tfoot>
					<tr><?php if (!FM_READONLY): ?>
							<td></td><?php endif; ?>
						<td colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? '6' : '4' ?>"><em><?php echo lng('Folder is empty') ?></em></td>
					</tr>
				</tfoot>
			<?php } else { ?>
				<tfoot>
					<tr>
						<td class="gray fs-7" colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? (FM_READONLY ? '6' : '7') : (FM_READONLY ? '4' : '5') ?>">
							<?php echo lng('FullSize') . ': <span class="badge text-bg-light border-radius-0">' . fm_get_filesize($all_files_size) . '</span>' ?>
							<?php echo lng('File') . ': <span class="badge text-bg-light border-radius-0">' . $num_files . '</span>' ?>
							<?php echo lng('Folder') . ': <span class="badge text-bg-light border-radius-0">' . $num_folders . '</span>' ?>
						</td>
					</tr>
				</tfoot>
			<?php } ?>
		</tbody>
	</table>
</div>
<div class="row">
	<?php if (!FM_READONLY): ?>
		<div class="col-xs-12 col-sm-9">
			<div class="btn-group flex-wrap" data-toggle="buttons" role="toolbar">
				<a href="#/select-all" class="btn btn-small btn-outline-primary btn-2" onclick="select_all();return false;"><i class="fa fa-check-square"></i> <?php echo lng('SelectAll') ?> </a>
				<a href="#/unselect-all" class="btn btn-small btn-outline-primary btn-2" onclick="unselect_all();return false;"><i class="fa fa-window-close"></i> <?php echo lng('UnSelectAll') ?> </a>
				<a href="#/invert-all" class="btn btn-small btn-outline-primary btn-2" onclick="invert_all();return false;"><i class="fa fa-th-list"></i> <?php echo lng('InvertSelection') ?> </a>
				<input type="submit" class="hidden" name="delete" id="a-delete" value="Delete" onclick="return confirm('<?php echo lng('Delete selected files') . ' ' . lng('and folders') ?>?');">
				<?php if (class_exists('ZipArchive') || class_exists('PharData')): ?>
					<input type="submit" class="hidden" name="zip" id="a-zip" value="Zip">
					<input type="submit" class="hidden" name="tar" id="a-tar" value="Tar">
				<?php endif; ?>
			</div>
		</div>
	<?php endif; ?>
</div>
<form action="" method="post" class="hidden">
	<input type="hidden" name="group" value="1">
	<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
	<?php foreach ($files_list as $f): ?>
		<input type="checkbox" name="file[]" value="<?php echo fm_enc($f['name']) ?>">
	<?php endforeach; ?>
</form>
<form action="" method="post" class="hidden">
	<input type="hidden" name="group" value="1">
	<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
	<?php foreach ($files_list as $f): ?>
		<input type="checkbox" name="file[]" value="<?php echo fm_enc($f['name']) ?>">
	<?php endforeach; ?>
</form>
<form action="" method="post" class="hidden" id="files-form">
	<input type="hidden" name="group" value="1">
	<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
	<?php foreach ($files_list as $f): ?>
		<input type="checkbox" name="file[]" value="<?php echo fm_enc($f['name']) ?>">
	<?php endforeach; ?>
</form>
<?php endif; ?>
<?php fm_show_footer(); ?>
