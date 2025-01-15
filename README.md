This is a simple script to aid with restoring WordPress websites back to clean and working condition. 

Usage:

** CWD to the WordPress directory before running the script ** 

<<<<<<< HEAD
gather_information:
&emsp;check_wp_version
&emsp;check_themes
&emsp;check_plugins
&emsp;verify_core
&emsp;verify_plugins
&emsp;user_list
&emsp;list-sessions

cleanup:
&emsp;reinstall_core
&emsp;delete_inactive_plugins
&emsp;delete_inactive_themes
&emsp;update_plugins
&emsp;update_themes
&emsp;destroy_admin_sessions
&emsp;cleanup_sessions
&emsp;reset_admin_passwords

list_oldplugins - Plugins that were NOT installed during past 15 minutes