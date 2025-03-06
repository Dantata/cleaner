#!/bin/bash

WP="$(which wp)"
if [[ -z "$WP" && "$1" != "help" ]]; then
    echo "Error: 'wp' command not found. Please ensure WP-CLI is installed and in your PATH."
    exit 1
fi
WP="$WP --path=$PWD --skip-themes --skip-plugins"
export SHELL_PIPE=0

function help {
    echo "WordPress Cleanup 1.0

Usage:
  $0 [COMMAND]
  $0 check                   - Run all functions in the 'check' category
  $0 check_wp_version        - Run a specific function
  $0 help                    - Show this page
    
Commands:

  check:
    check_wp_version           - Display the WordPress version and language
    check_auto_updates         - Check if automatic updates are enabled
    check_themes               - List installed themes
    check_plugins              - List installed plugins
    verify_core                - Run 'wp core verify-checksums'
    verify_plugins             - Run 'wp plugin verify-checksums --all'
    user_list                  - List all administrators
    list_admin_sessions        - List all sessions
    check_disallow_file_mods   - Check for DISALLOW_FILE_MODS in wp-config.php (prevents updates)

  clean:
    reinstall_core             - Reinstall WordPress using the latest version and keeping the language
    cleanup_plugins            - Delete inactive plugins
    cleanup_themes             - Delete inactive themes
    update_plugins             - Update all plugins
    update_themes              - Update all themes
    reinstall_plugins          - Reinstall all plugins
    reinstall_themes           - Reinstall all themes
    destroy_admin_sessions     - Destroy administrator sessions
    cleanup_sessions           - Destroy all user sessions
    reset_admin_passwords      - Reset passwords for all administrators
    list_old_plugins           - List plugins not installed in the past 15 minutes

  clean_keep_wp_version:
    ** same as <clean>, but keep the current WP version
    reinstall_core_keep_version             - Reinstall WordPress using the currently installed version and language


  scan:
    php_malware_scanner        - https://github.com/scr34m/php-malware-scanner

  untracked_files:
    list_non_plugins           - Check for files/dirs in /wp-content/plugins that don't belong to a plugin
    list_non_wp_files          - Check for files/dirs in the root WP directory that are not WordPress files (not recursive)
    "
}


	
function check {
	check_wp_version
	check_auto_updates
	check_themes
	check_plugins
	verify_core
	verify_plugins
	user_list
	list_admin_sessions
	check_disallow_file_mods
}

function clean {
	reinstall_core
	cleanup_plugins
	cleanup_themes
	update_plugins
	update_themes
	reinstall_plugins
	reinstall_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords
	disable_comments
	list_old_plugins
}

function clean_keep_wp_version {
	reinstall_core_keep_version
	cleanup_plugins
	cleanup_themes
	update_plugins
	update_themes
	reinstall_plugins
	reinstall_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords
	disable_comments
	list_old_plugins
}

function scan {
	php_malware_scanner
}

function untracked_files {
	list_non_plugins
	list_non_wp_files
}

# pre-cleanup functions:

function check_wp_version {
	echo -e "\nWordPress Version:\n---"
	#WPLANGUAGE=$($WP language core list --status=active --field=language)
	WPLANGUAGE=$($WP core version --extra | grep "Package language:" | awk {'print $NF'})

    WPVERSION=$($WP core version)
	echo -e "WP Version: " "$WPVERSION" "\nWP Language: " "$WPLANGUAGE"
}

function check_auto_updates {
	echo -e "\nChecking if automatic updates are enabled:\n---"
	$WP option list --search=auto_update_core*
	}

function check_themes {
	echo -e "\nInstalled Themes:\n---"
	$WP theme list
}
	
function check_plugins {
	echo -e "\nInstalled Plugins:\n---"
	$WP plugin list
}

function verify_core {
	echo -e "\nWP Core checksum:\n---"
    $WP core verify-checksums
}
	
function verify_plugins {
	echo -e "\nPlugins checksum:\n---"
    $WP plugin verify-checksums --all
}
	
function user_list {
	echo -e "\nWordPress Administrators:\n---"
    $WP user list --role=administrator
}

function list_admin_sessions {
	users=$($WP user list --role=administrator --field=id | sort)

	for user in $users; do
	  echo -e "\nActive sessions for user \"$user\":\n---"
	  $WP user session list "$user"
	  echo "session_tokens (active and expired) for user \"$user\":"
	  $WP user meta get $user session_tokens
	  
	done
}	
	
function check_disallow_file_mods {
	echo -e "\nChecking for DISALLOW_FILE_MODS:\n---"
	if grep "DISALLOW_FILE_MODS" wp-config.php; then
    :
		else
   		 echo "DISALLOW_FILE_MODS not found in wp-config.php"
	fi
}

# cleanup functions:

function reinstall_core {
	#WPLANGUAGE=$($WP language core list --status=active --field=language --skip-plugins --skip-themes)
	WPLANGUAGE=$($WP core version --extra | grep "Package language:" | awk {'print $NF'})
	#WPVERSION=$($WP core version)
	WPVERSION="latest"
	echo -e "\nReinstalling WP core (Version: $WPVERSION, Language: $WPLANGUAGE):\n---"
 	rm -rf wp-admin/ wp-includes/
 	$WP core download --force --skip-content --version=$WPVERSION --locale=$WPLANGUAGE
	rm -f wp-content/plugins/hello.php
	rm -rf wp-content/plugins/hello-dolly	
}

function reinstall_core_keep_version {
	#WPLANGUAGE=$($WP language core list --status=active --field=language --skip-plugins --skip-themes)
	#WPVERSION=$($WP core version)
	WPLANGUAGE=$($WP core version --extra | grep "Package language:" | awk {'print $NF'})
	WPVERSION=$($WP core version --extra | grep "WordPress version:" | awk {'print $NF'})
	#WPVERSION="latest"
	echo -e "\nReinstalling WP core (Version: $WPVERSION, Language: $WPLANGUAGE):\n---"
 	rm -rf wp-admin/ wp-includes/
 	$WP core download --force --skip-content --version=$WPVERSION --locale=$WPLANGUAGE
	rm -f wp-content/plugins/hello.php
	rm -rf wp-content/plugins/hello-dolly	
}

function cleanup_plugins {
	echo -e "\nDeleting inactive plugins:\n---"
    $WP plugin list --field=name --status=inactive | xargs -I {} $WP plugin delete {}
}

function cleanup_themes {
	echo -e "\nDeleting inactive themes:\n---"
	$WP theme list --field=name --status=inactive | xargs -I {} $WP theme delete {}
}
	
function update_plugins {
	echo -e "\nUpdating plugins:\n---"
	$WP plugin update --all
}
	
function update_themes {
	echo -e "\nUpdating themes:\n---"
	$WP theme update --all
}

function reinstall_plugins {
	echo -e "\nRe-installing all active plugins:\n---"
	#$WP plugin list --field=name --status=active | xargs -I {} wp plugin install {} --force
	$WP plugin list --field=name --status=active | xargs -I {} sh -c 'echo "$(printf "%q": {})"; wp plugin install --force "$(printf "%q" {})" 2>&1 | grep "Success\|Error"'
}

function reinstall_themes {
	echo -e "\nRe-installing all active themes:\n---"
	#$WP theme list --field=name --status=active | xargs -I {} wp theme install {} --force
	$WP theme list --field=name --status=active | xargs -I {} sh -c 'echo "$(printf "%q": {})"; wp theme install --force "$(printf "%q" {})" 2>&1 | grep "Success\|Error"'

}

function destroy_admin_sessions {
	echo -e "\nDestroying any admin sessions:\n---"
	$WP user list --role=administrator --field=ID | xargs -I {} $WP user session destroy {} --all
}

function cleanup_sessions {
	users=$($WP user list --field=id | sort)
	for user in $users; do
	  echo -e "\nDestrotying sessions for user $user:\n---"
	  $WP user session destroy $user --all	  
	done
}

function reset_admin_passwords {
	echo -e "\nResetting passwords of administrators:\n---"
	$WP user list --role=administrator --field=ID | xargs -I {} $WP user reset-password {}
	}
	
function list_old_plugins {
    # list plugins that have most probably not been reinstalled by this script
	echo -e "\nPlugins that were NOT installed during past 15 minutes:\n---"
	find wp-content/plugins -maxdepth 1 -mindepth 1 -type d -mmin +15 -exec basename {} \;
}

function disable_comments {
	echo -e "\nDisabling comments:\n---"
	wp post list --format=ids | xargs wp post update --comment_status=closed
}

# scanning functions

function php_malware_scanner {
	echo -e "\nRunning "PHP malware scanner"\n---"
	TMP_DIR=$(mktemp -d /tmp/$USER-php-malware-scanner-XXXXXX)
	cleanup() {
   		 echo "Cleaning up temporary files (rm -rf $TMP_DIR)."
   		 rm -rf "$TMP_DIR"
	}
	trap cleanup EXIT SIGINT SIGTERM
	git clone https://github.com/scr34m/php-malware-scanner.git $TMP_DIR -q
	php73.cli $TMP_DIR/scan.php -p -k -n -d $PWD -j $($WP core version) -w -c -s -t --disable-stats
}

function list_non_plugins {
	echo -e "\nFiles/Directories at wp-content/plugins not listed as plugins:\n---"
	find wp-content/plugins/ -maxdepth 1 -mindepth 1 -exec basename {} \; | grep -vxFf <(wp plugin list --field=name --skip-plugins --skip-themes)
}

# Obtain list of WP files at root:
# curl -s https://api.github.com/repos/WordPress/WordPress/git/trees/master?recursive=1 | jq -r '.tree[] | .path' | awk -F/ {'print $1'} | sort -u
# will be hard-coding this below since curl may be unavailable
function list_non_wp_files {
	echo -e "\nLooking for non-WP files/dirs in root directory:\n---"
	find . -maxdepth 1 -mindepth 1 -exec basename {} \; | grep -vxFf <(echo "index.php
license.txt
readme.html
wp-activate.php
wp-admin
wp-blog-header.php
wp-comments-post.php
wp-config-sample.php
wp-content
wp-cron.php
wp-includes
wp-links-opml.php
wp-load.php
wp-login.php
wp-mail.php
wp-settings.php
wp-signup.php
wp-trackback.php
xmlrpc.php
php.ini
.htaccess
.htpasswd
missing.html
favicon.ico
cgi-bin
wp-config.php")
}


function check_wp_config {
    if [ ! -f wp-config.php ]; then
        echo "Error: wp-config.php not found. Please run this script from the root folder of a WordPress installation."
        exit 1
    fi
}

function validate_and_run {
    if declare -f "$1" > /dev/null; then
        "$1"
    else
        echo "Error: Invalid command '$1'. Use 'help' for a list of available commands."
        exit 1
    fi
}

if [[ -z "$1" ]]; then
    help
    exit 0
fi

check_wp_config
validate_and_run "$1"
