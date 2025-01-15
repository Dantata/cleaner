#!/bin/bash

# Variables
WP="$(which wp) --path=$PWD --skip-themes --skip-plugins"
export SHELL_PIPE=0

function help {

	echo "WordPress cleanup 0.1

Usage:

** CWD to the WordPress directory before running the script ** 

ls:
	check_wp_version
	check_themes
	check_plugins
	verify_core
	verify_plugins
	user_list
	list_sessions

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
	
	"
}


function ls {
	check_wp_version
	check_themes
	check_plugins
	verify_core
	verify_plugins
	user_list
	list_sessions
	}

function clean {
	reinstall_core
	delete_inactive_plugins
	delete_inactive_themes
	update_plugins
	update_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords
	list_oldplugins
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
	  echo "Active sessions for user \"$user\":"
	  $WP user session list "$user"
	  echo "session_tokens (active and expired) for user \"$user\":"
	  $WP user meta get $user session_tokens
	  
	done
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

# main	
if [[ -z "$1" ]]; then
    help
fi
$1
