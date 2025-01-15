This is a simple script to aid with restoring WordPress websites back to clean and working condition. 

Usage:

** CWD to the WordPress directory before running the script ** 

gather_information:  
	check_wp_version  
	check_themes  
	check_plugins  
	verify_core  
	verify_plugins  
	user_list  
	list-sessions  

cleanup:
	reinstall_core
	delete_inactive_plugins
	delete_inactive_themes
	update_plugins
	update_themes
	destroy_admin_sessions
	cleanup_sessions
	reset_admin_passwords

list_oldplugins - Plugins that were NOT installed during past 15 minutes
