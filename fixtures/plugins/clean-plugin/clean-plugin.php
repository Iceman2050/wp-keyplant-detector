<?php
/*
Plugin Name: Clean Example Plugin
Plugin URI: https://example.com/clean-plugin
Description: A harmless example plugin used as a clean fixture.
Version: 1.2.3
Author: Example Author
Author URI: https://example.com/
*/

add_action('init', 'clean_example_init');
function clean_example_init() {
    echo 'clean';
}
