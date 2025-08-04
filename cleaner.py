#!/usr/bin/env python3

import sys
import os
import logging
import argparse
import tempfile # php_malware_scanner
import subprocess
from functools import lru_cache # for WPCLI_PATH


WPCLI_PATH = None  # Module-level variable

def setup_logging(verbose):
    """Logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        force=True  # reconfiguration
    )
    logging.debug(f"Logging level set to: {logging.getLevelName(level)}")

def check_environment():
    """ Check if WordPress exists in {args.path} """
    try:
        run_command(f"{WPCLI_PATH} core is-installed",
            "Checking WordPress installation",
            continue_on_error=False,
            silent=True)
        logging.debug("WordPress installation verified")
        return True
    except subprocess.CalledProcessError:
        logging.error("No WordPress installation found or WP-CLI cannot access it")
        return False

def run_command(command: str,
                comment: str = None,
                timeout: int = 600,
                debug: bool = False,
                continue_on_error: bool = False,
                silent: bool = False) -> str:
    """ Wrapper for bash commands """
    try:
        logging.debug(f"Executing command: {command}")
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True  # Automatically raises exception on non-zero exit
        )

        if not silent:
            if result.stdout.strip():
                if debug:
                    logging.debug(f"{comment}\n{result.stdout.strip()}")
                else:
                    logging.info(f"{comment}\n{result.stdout.strip()}")
            else:
                if debug:
                    logging.debug(f"{comment}\n--")
                else:
                    logging.info(f"{comment}\n--")

        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        # Command failed
        if not silent:
                  logging.error(f"Command failed: {command}")
                  logging.error(f"Exit code: {e.returncode}")
                  logging.error(f"Error output: {e.stderr.strip()}")
        else:
                  logging.debug(f"Command failed: {command}")
                  logging.debug(f"Exit code: {e.returncode}")
                  logging.debug(f"Error output: {e.stderr.strip()}")

        if continue_on_error:
            logging.warning("Continuing despite error due to continue_on_error=True")
            return e.stdout.strip() if e.stdout else ""
        raise

    except subprocess.TimeoutExpired as e:
        logging.error(f"Command timed out after {timeout}s: {command}")
        raise

@lru_cache(maxsize=1)
def ensure_wp_cli(path):
    """Ensure WP CLI is available, download if needed. Result is cached."""

    wp_path = f"--path={path}"
    wp_flags = "--skip-themes --skip-plugins --color"
    env_flags = "SHELL_PIPE=0"

    try:
        wpcli_path = run_command("which wp", "WP-CLI", silent=True).strip()
        logging.debug(f"Found system WP-CLI: {wpcli_path}")
        return f"{env_flags} {wpcli_path} {wp_flags} {wp_path}"
    except subprocess.CalledProcessError:
        pass

    if os.path.isfile("/tmp/wp-cli.phar-ok"):
           wpcli_path="/tmp/wp-cli.phar-ok"
           logging.debug(f"Found {wpcli_path}")

           if not os.access(wpcli_path, os.X_OK):
                os.chmod(wpcli_path, 0o755)
                logging.debug(f"Setting +x permissions for {wpcli_path}")

    try:
            result = run_command(f"{wpcli_path} --version",
                               #"Verifying WP-CLI",
                               silent=True,
                               debug=True,
                               timeout=10)
            if "WP-CLI" in result:
                logging.debug(f"Verified WP-CLI at {wpcli_path}")
                return f"{env_flags} {wpcli_path} {wp_flags} {wp_path}"
            else:
                logging.warning(f"File at {wpcli_path} doesn't appear to be WP-CLI")
                return False

    except subprocess.CalledProcessError:
            logging.warning(f"Failed to verify WP-CLI at {wpcli_path}")
            pass

    # WP CLI not found, need to download
    logging.debug("Downloading WP-CLI...")
    download_url = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
    download_methods = [
        f"GET {download_url} > /tmp/wp-cli.phar-ok",
        f"curl -o /tmp/wp-cli.phar-ok {download_url}",
        f"wget -O /tmp/wp-cli.phar-ok {download_url}"
    ]

    download_success = False
    for method in download_methods:
        try:
            run_command(method, f"Trying: {method}", debug=True)
            download_success = True
            break
        except subprocess.CalledProcessError:
            continue

    if not download_success:
        raise Exception("Failed to download WP CLI with GET, curl, or wget")

    if os.path.isfile("/tmp/wp-cli.phar-ok"):
        wpcli_path = "/tmp/wp-cli.phar-ok"
        os.chmod(wpcli_path, 0o755)
        logging.debug(f"Downloaded wp-cli.phar in /tmp: {wpcli_path}")
        return f"{env_flags} {wpcli_path} {wp_flags} {wp_path}"


def get_wp_path_from_wpcli():
    """ Getting wp_path to use in list_non_plugins() and list_non_wp_files() """
    import re
    path_match = re.search(r'--path=([^\s]+)', WPCLI_PATH)
    return path_match.group(1) if path_match else "."
###                       ###
### Check functions START ###
###                       ###

def check_wp_version():
    """ WP core version check """
    run_command(f"{WPCLI_PATH} core version --extra", "Checking the WordPress version")

def check_auto_updates():
    """ Check if auto-updates are enabled or disabled """
    run_command(f"{WPCLI_PATH} option list --search=auto_update_core*",
                "Checking if automatic updates are enabled")
    command="grep '^define.*WP_AUTO_UPDATE_' wp-config.php || echo WP_AUTO_UPDATE_* not found in wp-config.php"
    run_command(command, "Checking wp-config.php for WP_AUTO_UPDATE_*")

    command="! grep \"add_filter-*auto_update_plugin\" wp-content/* -r"
    run_command(command,
                "Checking /wp-content/* for add_filter-*auto_update_plugin")

    command="! grep \"add_filter-*auto_update_theme\" wp-content/* -r"
    run_command(command,
                "Checking /wp-content/* for add_filter-*auto_update_theme")

def update_core():
    """ Updated the WP core """
    run_command(f"{WPCLI_PATH} core update",
                "Updating the WordPress core",
                timeout=900)  # 15 minutes

def update_plugins():
    """ Update all plugins """
    run_command(f"{WPCLI_PATH} plugin update --all",
                "Updating all plugins",
                timeout=900)  # 15 minutes

def list_users():
    """ List all administrators """
    run_command(f"{WPCLI_PATH} user list --role=administrator --format=table",
                "Listing administrators")

def check_plugins():
    """ List all plugins """
    run_command(f"{WPCLI_PATH} plugin list --format=table",
                "Installed plugins")

def verify_core():
    """ Verify core checksums """
    run_command(f"{WPCLI_PATH} core verify-checksums",
                "Verifying WP core files")

def check_themes():
    """ List all themes """
    run_command(f"{WPCLI_PATH} theme list --format=table",
                "Installed themes")

def check_admin_sessions():
    """ List all administrators' sessions """
    command = f"{WPCLI_PATH} user list --role=administrator --field=id | sort | xargs -I {{}} sh -c 'echo User ID: {{}} && {WPCLI_PATH} user session list {{}}'"
    run_command(command,
                "Admin Sessions:")

def check_disallow_file_mods():
    """ Check for DISALLOW_FILE_MODS - it would disable updates in Dashboard """
    command="grep ^DISALLOW_FILE_MODS wp-config.php || echo DISALLOW_FILE_MODS not found in wp-config.php"
    run_command(command,
                "Checking wp-config.php for DISALLOW_FILE_MODS")

###                     ###
### Check functions END ###
###                     ###

def reinstall_core():
    """ Reinstall WP core """
    lang_cmd = f"{WPCLI_PATH} core version --extra | grep 'Package language:' | awk {{'print $NF'}}"
    wplanguage = run_command(lang_cmd, "Getting WordPress language", debug=True)

    if not wplanguage:
        wplanguage = "en_US"
        logging.warning("Could not detect language, using en_US")

    wpversion = "latest"
    run_command("rm -rf wp-admin/ wp-includes/", "Removing wp-admin and wp-includes", debug=True)
    run_command(
        f"{WPCLI_PATH} core download --force --skip-content --version={wpversion} --locale={wplanguage}",
        f"Attempting to reinstall core (version={wpversion}, locale={wplanguage})"
    )
    run_command("rm -f wp-content/plugins/hello.php", "Removing wp-content/plugins/hello.php", debug=True)
    run_command("rm -rf wp-content/plugins/hello-dolly", "Removing wp-content/plugins/hello-dolly", debug=True)

def reinstall_core_keep_version():
    """ Reinstall WP core, keep current version"""
    lang_cmd = f"{WPCLI_PATH} core version --extra | grep 'Package language:' | awk {{'print $NF'}}"
    wplanguage = run_command(lang_cmd,
                "Getting WordPress language", debug=True)

    if not wplanguage:
        wplanguage = "en_US"
        logging.warning("Could not detect language, using en_US")

    ver_cmd = f"({WPCLI_PATH} core version --extra | grep 'WordPress version:' | awk {{'print $NF'}})"
    wpversion = run_command(ver_cmd,
                "Getting WordPress Version", debug=True)

    run_command("rm -rf wp-admin/ wp-includes/", "Removing wp-admin and wp-includes")
    run_command(
        f"{WPCLI_PATH} core download --force --skip-content --version={wpversion} --locale={wplanguage}",
        f"Attempting to reinstall core (version={wpversion}, locale={wplanguage})"
    )
    run_command("rm -f wp-content/plugins/hello.php", "Removing wp-content/plugins/hello.php",)
    run_command("rm -rf wp-content/plugins/hello-dolly", "Removing wp-content/plugins/hello-dolly")

def cleanup_plugins():
    inactive_plugins = run_command(f"{WPCLI_PATH} plugin list --field=name --status=inactive", silent=True)
    
    if inactive_plugins:
        plugin_list = [plugin.strip() for plugin in inactive_plugins.split('\n') if plugin.strip()]
        
        if plugin_list:
            logging.info(f"Found {len(plugin_list)} inactive plugins to delete")
            success_count = 0
            
            for plugin in plugin_list:
                try:
                    run_command(f"{WPCLI_PATH} plugin delete {plugin}", f"Deleting plugin: {plugin}")
                    success_count += 1
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to delete plugin {plugin}: {e}")
            
            logging.info(f"Successfully deleted {success_count}/{len(plugin_list)} plugins")
        else:
            logging.info("No inactive plugins found")

def cleanup_themes():
    inactive_themes = run_command(f"{WPCLI_PATH} theme list --field=name --status=inactive", silent=True)
    
    if inactive_themes:
        theme_list = [theme.strip() for theme in inactive_themes.split('\n') if theme.strip()]
        
        if theme_list:
            logging.info(f"Found {len(theme_list)} inactive themes to delete")
            success_count = 0
            
            for theme in theme_list:
                try:
                    run_command(f"{WPCLI_PATH} theme delete {theme}", f"Deleting theme: {theme}")
                    success_count += 1
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to delete theme {theme}: {e}")
            
            logging.info(f"Successfully deleted {success_count}/{len(theme_list)} themes")
        else:
            logging.info("No inactive themes found")
            
def update_plugins():
    """ Update all plugins """
    run_command(f"{WPCLI_PATH} plugin update --all",
                "Updating all plugins")

def update_themes():
    """ Update all themes """
    run_command(f"{WPCLI_PATH} theme update --all",
                "Updating all themes")

def reinstall_plugins():
    """ Reinstall all plugins """
    try:
        plugins = run_command(f"{WPCLI_PATH} plugin list --field=name", debug=True)
        plugin_list = [p.strip() for p in plugins.split('\n') if p.strip()]
    except:
        logging.error("Failed to get plugin list")
        return

    logging.info(f"Reinstalling {len(plugin_list)} plugins:")

    for plugin in plugin_list:
        old_ver = get_plugin_version(plugin)

        if reinstall_plugin(plugin):
            new_ver = get_plugin_version(plugin)

            if old_ver != new_ver and old_ver != "unknown" and new_ver != "unknown":
                print(f"{plugin} = updated to {new_ver} (was {old_ver})")
            else:
                print(f"{plugin} = reinstalled same version ({new_ver})")
        else:
            print(f"{plugin} = failed")

def get_plugin_version(plugin_name: str) -> str:
    """Get plugin version, return 'unknown' if failed."""
    try:
        return run_command(f"{WPCLI_PATH} plugin get {plugin_name} --field=version", silent=True).strip()
    except:
        return "unknown"

def reinstall_plugin(plugin_name: str) -> bool:
    """Reinstall plugin, return True if successful."""
    try:
        run_command(f"{WPCLI_PATH} plugin install {plugin_name} --force", silent=True)
        return True
    except:
        return False

def reinstall_themes():
    """Reinstall all active themes with simple status output."""
    # Get active themes
    try:
        themes = run_command(f"{WPCLI_PATH} theme list --field=name")
        theme_list = [p.strip() for p in themes.split('\n') if p.strip()]
    except:
        logging.error("Failed to get theme list")
        return

    logging.info(f"Reinstalling {len(theme_list)} themes:")

    for theme in theme_list:
        # Get versions and reinstall
        old_ver = get_theme_version(theme)

        if reinstall_theme(theme):
            new_ver = get_theme_version(theme)

            if old_ver != new_ver and old_ver != "unknown" and new_ver != "unknown":
                print(f"{theme} = updated to {new_ver} (was {old_ver})")
            else:
                print(f"{theme} = reinstalled same version ({new_ver})")
        else:
            print(f"{theme} = failed")

def get_theme_version(theme_name: str) -> str:
    """Get theme version, return 'unknown' if failed."""
    try:
        return run_command(f"{WPCLI_PATH} theme get {theme_name} --field=version", silent=True).strip()
    except:
        return "unknown"

def reinstall_theme(theme_name: str) -> bool:
    """Reinstall theme, return True if successful."""
    try:
        run_command(f"{WPCLI_PATH} theme install {theme_name} --force", silent=True)
        return True
    except:
        return False

def destroy_admin_sessions():
    """ Destroy all admin sessions """
    try:
        administrators = run_command(f"{WPCLI_PATH} user list --role=administrator --field=ID", silent=True)
        administrators_list = [p.strip() for p in administrators.split('\n') if p.strip()]
    except:
        logging.error("Failed to get administrators")
        return
        
    logging.info("Destroying administrators' sessions")
    for admin in administrators_list:
            run_command(f"{WPCLI_PATH} user session destroy {admin} --all")

def cleanup_sessions():
    """ Destroy ALL sessions """
    try:
        users = run_command(f"{WPCLI_PATH} user list --field=ID", silent=True)
        user_list = [p.strip() for p in users.split('\n') if p.strip()]
    except:
        logging.error("Failed to get administrators")
        return
        
    logging.info("Destroying users sessions")
    for user in user_list:
            run_command(f"{WPCLI_PATH} user session destroy {user} --all")
    
def list_old_plugins():
    """ List plugins that haven't been updated within the last 15 minutes """
    run_command("find wp-content/plugins -maxdepth 1 -mindepth 1 -type d -mmin +15 -exec stat -c '%n %z' {} \; | column -t", "Plugins that were NOT installed or updated in the last 15 minutes")

def disable_comments():
    """Disable comments using Python approach."""
    try:
        # Get post IDs using your full WPCLI_PATH
        post_ids = run_command(f"{WPCLI_PATH} post list --format=ids", "Getting post IDs", debug=True).strip()

        if not post_ids:
            logging.info("No posts found")
            return

        # Update all posts at once using your full WPCLI_PATH
        run_command(f"{WPCLI_PATH} post update {post_ids} --comment_status=closed", "Disabling comments for ALL posts")

    except Exception as e:
        logging.error(f"Failed to disable comments: {e}")
        raise

###
### Misc Functions
###

def php_malware_scanner():
    """Run PHP malware scanner with comprehensive error handling."""
    logging.info("Starting PHP malware scanner")

    # Check prerequisites
    try:
        run_command("git --version", "Checking git availability", debug=True)
        run_command("php --version", "Checking PHP availability", debug=True)
    except subprocess.CalledProcessError:
        logging.error("Missing prerequisites: git and php are required")
        raise

    with tempfile.TemporaryDirectory(prefix=f"{os.getenv('USER', 'user')}-php-malware-scanner-") as tmp_dir:
        try:
            logging.info(f"Using temporary directory: {tmp_dir}")

            # Clone the repository
            run_command(
                f"git clone https://github.com/scr34m/php-malware-scanner.git {tmp_dir} -q",
                "Cloning PHP malware scanner repository"
            )

            # Verify scanner was downloaded
            scanner_path = os.path.join(tmp_dir, "scan.php")
            if not os.path.exists(scanner_path):
                raise FileNotFoundError(f"Scanner not found at {scanner_path}")

            # Get WordPress version
            wp_version = run_command(
                f"{WPCLI_PATH} core version",
                "Getting WordPress version",
                debug=True
            ).strip()

            logging.info(f"Scanning WordPress {wp_version} in {os.getcwd()}")

            # Run the scanner
            scanner_command = (
                f"php {scanner_path} "
                f"-p -k -n -d {os.getcwd()} -j {wp_version} "
                f"-w -c -s -t --disable-stats"
            )

            run_command(scanner_command, "Running PHP malware scanner")
            logging.info("Malware scan completed")

        except subprocess.CalledProcessError as e:
            logging.error(f"PHP malware scanner failed: {e}")
            raise
        except FileNotFoundError as e:
            logging.error(f"Scanner file not found: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during malware scan: {e}")
            raise

def list_non_plugins():
    """ List files/directories in /wp-content/plugins that don't show up at `wp plugin list` """
    wp_path = get_wp_path_from_wpcli()
    result = run_command(f"find {wp_path}/wp-content/plugins/ -maxdepth 1 -mindepth 1 ! -name index.php -exec basename {{}} \; | grep -vxFf <({WPCLI_PATH} plugin list --field=name --skip-plugins --skip-themes)", "Files/directories in /wp-content/plugins that are NOT plugins", silent=True)
    if result:
        all_items = [item.strip() for item in result.split('\n') if item.strip()]
        files_string = " ".join(f'"{item}"' for item in all_items)
        run_command(f"cd {wp_path}/wp-content/plugins; stat -c '%n|%z' {files_string} | column -t -s '|'|  sort -k2,3", "Non-plugins in /wp-content/plugins (format: file ctime)")

def list_non_wp_files():
    """ List all files in the root not part of WordPress """
    wp_path = get_wp_path_from_wpcli()
    logging.debug("Non-WP files/dirs in root directory")
    wp_standard_files = {
        "index.php", "license.txt", "readme.html", "wp-activate.php",
        "wp-admin", "wp-blog-header.php", "wp-comments-post.php",
        "wp-config-sample.php", "wp-content", "wp-cron.php",
        "wp-includes", "wp-links-opml.php", "wp-load.php",
        "wp-login.php", "wp-mail.php", "wp-settings.php",
        "wp-signup.php", "wp-trackback.php", "xmlrpc.php",
        "php.ini", ".htaccess", ".htpasswd", "missing.html",
        "favicon.ico", "cgi-bin", "wp-config.php", ".user.ini", ".ftpaccess"
    }

    result = run_command(f"find {wp_path} -maxdepth 1 -mindepth 1 -exec basename {{}} \;",
                        silent=True)

    if result:
        all_items = [item.strip() for item in result.split('\n') if item.strip()]
        non_wp_items = [item for item in all_items if item not in wp_standard_files]

        if non_wp_items:
            files_string = " ".join(non_wp_items)
            stat_result = run_command(f'cd {wp_path}; stat -c "%n %z" {files_string} | column -t | sort -k2,3', silent=True)
            logging.info("Non-WP files/dirs in root directory (format: file ctime):\n" + stat_result)
        else:
            logging.info("No non-WP files found")

        return non_wp_items

    return []

def dir_path(path):
    """ Construct the path from argparse """
    if os.path.isdir(path):
        logging.info("WordPress Path: %s", path)
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")

def get_available_functions():
    """Get list of available functions."""
    return [
        'check_wp_version',
        'check_auto_updates', 
        'check_plugins',
        'verify_core',
        'check_themes',
        'list_users',
        'check_admin_sessions',
        'check_disallow_file_mods',
        'list_non_plugins',
        'list_non_wp_files',
        'reinstall_core',
        'update_core',
        'update_plugins',
        'reinstall_plugins',
        'reinstall_themes',
        'destroy_admin_sessions',
        'cleanup_sessions',
        'list_old_plugins',
        'disable_comments',
        'cleanup_plugins',
        'cleanup_themes',
        'php_malware_scanner'
    ]

def setup_arguments():
    """Setup and parse command line arguments."""
    available_functions = get_available_functions()
    
    parser = argparse.ArgumentParser(
        description='WordPress Scanner and Cleaner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-p', '--path',
                       default=os.getcwd(),
                       type=dir_path,
                       help='The path to the WordPress installation. Default: current directory')
    
    parser.add_argument('-t', '--scan-type',
                       choices=['check', 'clean', 'scan', 'untracked_files'],
                       default='check',
                       help='Type of scan to perform')
    
    parser.add_argument('-f', '--function',
                       choices=available_functions,
                       metavar='FUNC',
                       help='Run a specific function only. Options:\n  ' + '\n  '.join(available_functions))
    
    parser.add_argument('-v', '--verbose', '--debug',
                       action='store_true',
                       help='Enable verbose/debug output')
    
    args = parser.parse_args()
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    return args

def setup_environment(args):
    """Setup logging and WP-CLI environment."""
    setup_logging(args.verbose)
    
    global WPCLI_PATH
    WPCLI_PATH = ensure_wp_cli(args.path)
    
    if not check_environment():
        logging.error("WordPress environment check failed")
        sys.exit(1)

def execute_function(function_name):
    """Execute a specific function by name."""
    if hasattr(sys.modules[__name__], function_name):
        func = getattr(sys.modules[__name__], function_name)
        func()
    else:
        logging.error(f"Function {function_name} not found")
        sys.exit(1)

def execute_scan_type(scan_type):
    """Execute functions based on scan type."""
    if scan_type == 'check':
        functions = [
            check_wp_version,
            check_auto_updates,
            verify_core,
            check_plugins,
            check_themes,
            list_users,
            check_admin_sessions,
            check_disallow_file_mods,
            list_non_plugins,
            list_non_wp_files
        ]
        
        for i, func in enumerate(functions):
            func()
            if i < len(functions) - 1:  # Don't print after the last function
                print()
                
    elif scan_type == 'clean':
        functions = [
            reinstall_core,
            #update_core,
            cleanup_plugins,
            cleanup_themes,
            update_plugins,
            reinstall_plugins,
            reinstall_themes,
            destroy_admin_sessions,
            cleanup_sessions,
            disable_comments,
            list_old_plugins,
            list_non_plugins
        ]
        
        for i, func in enumerate(functions):
            func()
            if i < len(functions) - 1:  # Don't print after the last function
                print()
                
    elif scan_type == 'scan':
        php_malware_scanner()
        
    elif scan_type == 'untracked_files':
        list_non_plugins()
        list_non_wp_files()

def main():
    """Main function - orchestrates the entire program."""
    try:
        # Setup
        args = setup_arguments()
        setup_environment(args)
        
        # Execute based on arguments
        if args.function:
            execute_function(args.function)
        else:
            execute_scan_type(args.scan_type)
            
        return 0  # Success
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user (Ctrl+C)")
        logging.info("Script interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())