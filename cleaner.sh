#!/bin/bash

# Variables
WP="$(which wp) --path=$PWD --skip-themes --skip-plugins"
export SHELL_PIPE=0

function help {

	echo "WordPress cleanup 0.1

Usage:

** Navigate to the WordPress directory before running the script ** 

check:
	check_wp_version
	check_themes
	check_plugins
	verify_core
	verify_plugins
	user_list
	list_sessions
	check_disallow_file_mods

clean:
	reinstall_core
	delete_inactive_plugins
	delete_inactive_themes
	update_plugins
	update_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords
	list_oldplugins - Plugins that were NOT installed during past 15 minutes
	
scan:
	php_malware_scanner
	"
}

function default {
	if [ ! -f wp-config.php ];
	then
		echo "wp-config.php not found - please run from the root folder of WordPress install."
		exit 1
	fi
}
	
function check {
	check_wp_version
	check_themes
	check_plugins
	verify_core
	verify_plugins
	user_list
	list_sessions
	check_disallow_file_mods
}

function clean {
	reinstall_core
	delete_inactive_plugins
	delete_inactive_themes
	update_plugins
	update_themes
	reinstall_plugins
	reinstall_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords
	disable_comments
	list_oldplugins
}

function scan {
	php_malware_scanner
}

# pre-cleanup functions:

function check_wp_version {
	echo -e "\nWordPress Version:\n---"
	WPLANGUAGE=$($WP language core list --status=active --field=language)
    WPVERSION=$($WP core version)
	echo -e "WP Version: " "$WPVERSION" "\nWP Language: " "$WPLANGUAGE" | column -t
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

function list_sessions {
	users=$($WP user list --field=id | sort)

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
	WPLANGUAGE=$($WP language core list --status=active --field=language)
	WPVERSION=$($WP core version)
	echo -e "\nReinstalling WP core (Version: $WPVERSION, Language: $WPLANGUAGE):\n---"
 	rm -rf $WP_PATH/wp-admin $WP_PATH/wp-includes
 	$WP core download --force --skip-content --version=$WPVERSION --locale=$WPLANGUAGE
	# good bye, dolly...
	#rm -f wp-content/plugins/hello.php
	#rm -rf wp-content/plugins/hello-dolly	
}

function delete_inactive_plugins {
	echo -e "\nDeleting inactive plugins:\n---"
    $WP plugin list --field=name --status=inactive | xargs -I {} $WP plugin delete {}
}

function delete_inactive_themes {
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
	echo "\nRe-installing all active plugins:\n---"
	$WP plugin list --field=name --status=active | xargs -I {} wp plugin install {} --force
}

function reinstall_themes {
	echo "\nRe-installing all active themes:\n---"
	$WP theme list --field=name --status=active | xargs -I {} wp theme install {} --force
}

function destroy_admin_sessions {
	echo -e "\nDestroying any admin sessions:\n---"
	$WP user list --role=administrator --field=ID | xargs -I {} $WP user session destroy {}
}

function cleanup_sessions {
	users=$($WP user list --field=id | sort)
	for user in $users; do
	  echo "Destrotying sessions for user $user:"
	  $WP user session destroy $user --all	  
	done
}

function reset_admin_passwords {
	echo -e "\nResetting passwords of administrators:\n---"
	$WP user list --role=administrator --field=ID | xargs -I {} $WP user reset-password {}
	}
	
function list_oldplugins {
    # list plugins that have most probably not been reinstalled by this script
	echo "Plugins that were NOT installed during past 15 minutes:"
	find wp-content/plugins -maxdepth 1 -type d -mmin +15 -exec basename {} \;
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


# main	
if [[ -z "$1" ]]; then
    help
    default
fi

if [ "$1" == "help" ]; then
	help
fi
#default
$1
