#!/usr/bin/env python3
import paramiko
import xml.etree.ElementTree as ET
import logging
import sys
import time
import re
import os
from datetime import datetime
from typing import Dict, Tuple, Optional, List, Any

# --- Configuration ---
CONFIG_FILE = 'config.xml'
LOG_FILE = 'ise-restore-log.txt'
# CERT_KEYS_FILENAME_STORE = 'cert_keys_backup_filename.txt' # File not used if reading name from config.xml
CONFIG_FILENAME_STORE = 'backup_filename.txt' # Still used for the main config backup filename
DEFAULT_REPO_NAME = "FTP-Repo"

# --- Logging Setup ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filemode='w' # Start fresh log for restore attempt
)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)
logging.getLogger("paramiko").setLevel(logging.WARNING)


# --- Helper Functions ---

def read_config() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Reads config.xml, including the fixed CA keys filename for import."""
    logging.info(f"Reading configuration from {CONFIG_FILE}")
    try:
        tree = ET.parse(CONFIG_FILE)
        root = tree.getroot()
        ise, ftp, backup = root.find('ise'), root.find('ftp'), root.find('backup')

        if not all([ise, ftp, backup]):
            raise ValueError("Missing required sections (ise, ftp, backup) in config.xml")

        def extract_config(element: ET.Element, section_name: str) -> Dict[str, str]:
            conf = {child.tag: child.text for child in element if child.text is not None}
            # Define required keys for each section
            required = {
                'ise': ['hostname', 'username', 'password'],
                'ftp': ['hostname', 'username', 'password', 'backup_dir'],
                # ca_keys_fixed_filename is required for restore import
                'backup': ['name', 'encryption_key', 'ca_keys_fixed_filename']
            }
            if section_name in required:
                 for key in required[section_name]:
                     if key not in conf or not conf[key] or not conf[key].strip():
                         raise ValueError(f"Missing or empty value for '{key}' in '{section_name}' section")
            return conf

        ise_config = extract_config(ise, 'ise')
        ftp_config = extract_config(ftp, 'ftp')
        backup_config = extract_config(backup, 'backup') # Includes ca_keys_fixed_filename

        # Validate encryption key format
        key = backup_config.get('encryption_key', '')
        if len(key) < 8 or not any(char.isdigit() for char in key):
            raise ValueError("Backup encryption key must be >= 8 chars and include a digit.")

        logging.info("Configuration read successfully.")
        logging.info(f"Using fixed CA keys filename from config for import: {backup_config['ca_keys_fixed_filename']}")
        return ise_config, ftp_config, backup_config

    except ET.ParseError as e:
        logging.critical(f"FATAL: Error parsing {CONFIG_FILE}: {e}", exc_info=True)
        sys.exit(f"FATAL: Error parsing {CONFIG_FILE}: {e}")
    except ValueError as e:
        logging.critical(f"FATAL: Configuration validation error: {e}", exc_info=True)
        sys.exit(f"FATAL: Configuration validation error: {e}")
    except Exception as e:
        logging.critical(f"FATAL: Error reading configuration: {e}", exc_info=True)
        sys.exit(f"FATAL: Error reading configuration: {e}")

def ssh_connect(ise_config: Dict[str, str], max_retries: int = 3, retry_delay: int = 20) -> Optional[paramiko.SSHClient]:
    """Establishes SSH connection to the ISE node."""
    hostname = ise_config['hostname']
    logging.info(f"Attempting SSH connection to {hostname}...")
    ssh = None
    for attempt in range(1, max_retries + 1):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname,
                username=ise_config['username'],
                password=ise_config['password'],
                timeout=30,       # Connection timeout
                banner_timeout=45 # Timeout for receiving SSH banner
            )
            logging.info(f"SSH connection to {hostname} established successfully.")
            return ssh
        except paramiko.AuthenticationException:
            logging.critical(f"Authentication failed for {ise_config['username']}@{hostname}.")
            if ssh: ssh.close()
            return None # No point retrying on auth failure
        except Exception as e:
            # Log other exceptions like timeout, connection refused, etc.
            logging.warning(f"SSH connection attempt {attempt}/{max_retries} to {hostname} failed: {type(e).__name__} - {e}", exc_info=False)
            if ssh: ssh.close() # Close if partially opened
            if attempt < max_retries:
                logging.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logging.critical(f"All SSH connection attempts to {hostname} failed.")
                return None
    return None # Should not be reached, but added for safety

def wait_for_output(shell: paramiko.Channel, prompt_regex: str = r'[#>]\s*$', timeout: int = 30, interval: float = 0.5) -> str:
    """Waits for specific prompt regex in the shell output."""
    start_time = time.time()
    buffer = ""
    logging.debug(f"Waiting for output (prompt: '{prompt_regex}', timeout: {timeout}s)")
    while time.time() - start_time < timeout:
        if shell.recv_ready():
            try:
                # Read larger chunks potentially
                chunk = shell.recv(8192).decode("utf-8", errors='ignore')
                logging.debug(f"Received chunk: {chunk.strip()}")
                buffer += chunk
                if chunk:
                    start_time = time.time() # Reset timeout if we received data
            except Exception as e:
                 logging.warning(f"Error receiving data from shell: {e}")
                 time.sleep(interval) # Wait before trying recv again
                 continue

        # Check if the expected prompt is found at the end of the buffer
        # Strip trailing whitespace before checking regex to handle prompt variations
        stripped_buffer = buffer.rstrip()
        if re.search(f"{prompt_regex}$", stripped_buffer):
             logging.debug(f"Prompt '{prompt_regex}' detected at end of stripped buffer.")
             break
        # Fallback: Check if prompt exists anywhere in the last N chars (e.g., 500)
        # Useful if prompt isn't exactly at the end due to delays/extra output
        elif re.search(prompt_regex, buffer[-500:]):
             logging.debug(f"Prompt '{prompt_regex}' detected within last 500 chars.")
             break

        # Explicit check for timeout condition inside the loop
        if time.time() - start_time >= timeout:
            logging.warning(f"Timeout reached waiting for output matching prompt '{prompt_regex}'")
            break # Exit loop on timeout

        time.sleep(interval) # Small sleep if no data received or prompt not found yet

    # Log final buffer state regardless of finding the prompt or timeout
    logging.debug(f"wait_for_output returning buffer (len={len(buffer)}):\n{buffer[-500:]}")
    return buffer

def monitor_process(shell: paramiko.Channel, completion_pattern: str, error_patterns: List[str], timeout_minutes: int = 30, progress_interval: int = 10, interactive_prompts: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    """Monitors a long-running process, handles interactive prompts, checks for completion/errors."""
    completion_regex = re.compile(completion_pattern, re.IGNORECASE)
    error_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in error_patterns]
    prompt_regexes = {}
    if interactive_prompts:
        # Use IGNORECASE, remove DOTALL as prompts are single-line
        prompt_regexes = {re.compile(p, re.IGNORECASE): r for p, r in interactive_prompts.items()}
        logging.debug(f"Compiled interactive prompt regexes: {[p.pattern for p in prompt_regexes.keys()]}")

    logging.info(f"Monitoring process for completion '{completion_regex.pattern}' (Timeout: {timeout_minutes} mins)")

    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    full_output = ""
    last_progress_time = time.time()
    responded_prompts = set()
    last_checked_len = 0 # Track how much output we've already checked for prompts

    while time.time() - start_time < timeout_seconds:
        received_data = False
        latest_chunk = ""
        if shell.recv_ready():
            try:
                latest_chunk = shell.recv(8192).decode("utf-8", errors='ignore')
                if latest_chunk:
                    received_data = True
                    full_output += latest_chunk
                    print(latest_chunk, end='', flush=True) # Print progress to console
                    logging.debug(f"Process output chunk: {latest_chunk.strip()}")
                    last_progress_time = time.time() # Update time of last received output
            except Exception as e:
                logging.warning(f"Exception reading from shell during monitor: {e}")

        # 1. Check for process completion
        if completion_regex.search(full_output):
            logging.info("Process completed successfully (completion pattern found).")
            print("\nProcess completed successfully.")
            return True, full_output

        # 2. Check for errors (more efficient to check latest chunk first)
        check_string = latest_chunk if received_data else full_output[-1024:] # Check recent or last 1k chars
        for err_regex in error_regexes:
            if err_regex.search(check_string):
                logging.error(f"Error pattern '{err_regex.pattern}' detected.")
                print(f"\nERROR pattern '{err_regex.pattern}' detected.")
                return False, full_output

        # 3. Check for interactive prompts in the *new* part of the output
        if prompt_regexes and (received_data or len(full_output) > last_checked_len) :
            # Search the portion of output received since the last check
            search_area = full_output[last_checked_len:]
            logging.debug(f"Checking for prompts in new output (len={len(search_area)}): '{search_area[-200:]}'") # Log tail

            prompt_found_in_chunk = False
            for prompt_re, response in prompt_regexes.items():
                match = prompt_re.search(search_area) # Search only the new data
                prompt_key = prompt_re.pattern
                if match and prompt_key not in responded_prompts:
                    logging.info(f"Detected prompt '{prompt_key}' in new output. Sending response '{response}'.")
                    print(f"\nResponding '{response}'...")
                    try:
                        shell.send(response + "\n")
                        responded_prompts.add(prompt_key) # Mark as responded
                        time.sleep(2) # Wait briefly after responding
                        prompt_found_in_chunk = True
                    except Exception as send_e:
                         logging.error(f"Failed to send response to prompt '{prompt_key}': {send_e}")
                         return False, full_output # Fatal error if response fails
                    break # Respond to only one prompt per check cycle

            # Update the position marker *after* checking all prompts for the current new data
            last_checked_len = len(full_output)

        # If no data received, pause briefly
        if not received_data:
             time.sleep(1) # Avoid busy-waiting

        # Check for prolonged inactivity
        if time.time() - last_progress_time > progress_interval * 60:
            logging.warning(f"No output received for {progress_interval} minutes.")
            print(f"\nWarning: No output received for {progress_interval} minutes.")
            last_progress_time = time.time() # Reset warning timer

        # Check if shell is still active
        if not shell.active:
             logging.error("Shell became inactive during monitored process.")
             print("\nERROR: Shell connection lost.")
             return False, full_output

    # If loop exits due to timeout
    logging.error(f"Process timed out after {timeout_minutes} minutes waiting for '{completion_regex.pattern}'.")
    print(f"\nERROR: Process timed out after {timeout_minutes} minutes.")
    return False, full_output

def execute_interactive_commands(ssh: paramiko.SSHClient, commands: List[str], timeout: int = 45, prompt_regex: Optional[str] = None) -> Tuple[bool, str]:
    """Executes simple, non-menu CLI commands interactively."""
    if prompt_regex is None:
        prompt_regex = r'\w+/\w+[#>] *$' # Default ISE prompt
    logging.info(f"Executing interactive commands: {commands} (prompt: {prompt_regex})")
    full_output = ""
    shell = None
    try:
        shell = ssh.invoke_shell()
        # Wait longer for initial prompt, might include login banner etc.
        output_buffer = wait_for_output(shell, prompt_regex=prompt_regex, timeout=30)
        full_output += output_buffer
        if not re.search(prompt_regex, output_buffer.rstrip()): # Check prompt at end
            logging.warning(f"Did not receive expected initial prompt matching '{prompt_regex}'. Output buffer tail:\n{output_buffer[-500:]}")
            # Don't fail here, attempt to proceed
        logging.debug(f"Initial shell output handled (len={len(output_buffer)}).")

        for command in commands:
            logging.info(f"Sending command: {command}")
            print(f"Executing: {command}")
            shell.send(command + "\n")
            output = wait_for_output(shell, prompt_regex=prompt_regex, timeout=timeout)
            full_output += output
            # Isolate output specific to this command for logging/printing
            new_output = output
            # Try to find the command echo and print from there
            cmd_echo_pos = output.rfind(command) # Find last occurrence in case of repetition
            if cmd_echo_pos != -1:
                 # Start looking for output after the command and the newline echo
                 start_pos = cmd_echo_pos + len(command) + 1
                 # Find the prompt specific to *this* command's output section
                 prompt_match = re.search(prompt_regex, output[start_pos:])
                 if prompt_match:
                      # Extract text between command echo and the next prompt
                      new_output = output[start_pos : start_pos + prompt_match.start()]
                 else:
                      # If prompt not found after command (unlikely), take everything after echo
                      new_output = output[start_pos:]
            else:
                # If command echo not found, use the whole output chunk (best effort)
                 new_output = output

            logging.info(f"Output for '{command}':\n{new_output.strip()}")
            print(f"Output:\n{new_output.strip()}")

            # Basic error checking in the command's output section
            # Convert to lower for case-insensitive checks
            lower_new_output = new_output.lower()
            # *** Be careful with generic error checks if expected output contains error strings ***
            # Example: "% repository not found" is expected negative output, not a script failure
            # Modify this check if needed for specific commands like 'show repository'
            if "% invalid" in lower_new_output or \
               "syntax error" in lower_new_output or \
               ("error:" in lower_new_output and "repository not found" not in lower_new_output) or \
               ("fail" in lower_new_output and command != "show application status ise") or \
               "aborted" in lower_new_output:
                # Added exclusions for expected "error" strings
                logging.error(f"Error detected executing command: {command}")
                print(f"ERROR detected executing command: {command}")
                if shell and shell.active: shell.close()
                return False, full_output

        if shell and shell.active: shell.close()
        logging.info("Interactive commands executed successfully.")
        return True, full_output

    except Exception as e:
        logging.error(f"Interactive command execution failed: {e}", exc_info=True)
        print(f"Interactive command execution failed: {e}")
        if shell and shell.active: shell.close()
        return False, full_output + f"\nException: {str(e)}"

def check_repository_exists(ssh: paramiko.SSHClient, repo_name: str) -> bool:
    """Checks if a repository exists using 'show repository'."""
    logging.info(f"Checking if repository '{repo_name}' exists...")
    commands = [f"show repository {repo_name}"]
    prompt_regex = r'\w+/\w+[#>] *$'
    # Use execute_interactive_commands which handles shell creation/closing
    success, output = execute_interactive_commands(ssh, commands, timeout=75, prompt_regex=prompt_regex)
    # Determine existence based on output content, independent of generic error check in execute_interactive_commands
    exists = "% Repository not found" not in output
    if not success and not exists:
        # If command failed AND repo not found text is absent, assume failure
        logging.error(f"Command execution failed AND repository '{repo_name}' was not found (or output unclear).")
        # Optionally return False or raise an exception depending on desired behavior
        return False # Treat as repo doesn't exist or can't be checked
    elif not success and exists:
         # Command failed but output didn't say "not found" - ambiguous, maybe repo exists but command had other issues
         logging.warning(f"Command execution failed but repository '{repo_name}' might exist (output didn't contain 'not found'). Proceeding cautiously.")
         return True # Assume it exists if the specific "not found" message isn't there

    # If command succeeded:
    logging.info(f"Repository '{repo_name}' {'exists' if exists else 'does not exist'}.")
    print(f"Repository '{repo_name}' {'exists' if exists else 'does not exist'}.")
    return exists

# --- CORRECTED create_repository FUNCTION ---
def create_repository(ssh: paramiko.SSHClient, repo_name: str, ftp_config: Dict[str, str]) -> bool:
    """Creates the FTP repository on the ISE device using configuration mode."""
    logging.info(f"Creating repository '{repo_name}'...")
    print(f"Creating repository '{repo_name}'...")
    ftp_url = f"ftp://{ftp_config['hostname']}/{ftp_config['backup_dir']}"
    # Define specific prompts for different config modes
    config_prompt_regex = r'\w+\(config\)#[ ]*$'
    # --- CORRECTED Regex: Dynamically include the repo name and handle case ---
    # Use an f-string and re.escape to handle potential special characters in repo_name
    # Use (?i) for case-insensitive matching of 'config-repository'
    repo_config_prompt_regex = rf'(?i)\w+\(config-repository-{re.escape(repo_name)}\)#[ ]*$'
    # --- END CORRECTION ---
    end_prompt_regex = r'\w+/\w+[#>] *$' # Back to normal exec prompt

    shell = None
    try:
        shell = ssh.invoke_shell()
        initial_output = wait_for_output(shell, prompt_regex=end_prompt_regex, timeout=20)
        if not re.search(end_prompt_regex, initial_output.rstrip()):
             logging.warning("Did not get expected initial prompt before configure terminal.")
             # Attempt to proceed anyway

        logging.info("Sending: configure terminal")
        shell.send("configure terminal\n")
        conf_output = wait_for_output(shell, prompt_regex=config_prompt_regex, timeout=15)
        if not re.search(config_prompt_regex, conf_output.rstrip()):
             raise RuntimeError(f"Did not get config prompt ({config_prompt_regex}). Got:\n{conf_output}")

        logging.info(f"Sending: repository {repo_name}")
        shell.send(f"repository {repo_name}\n")
        # Wait for the *corrected* repository config prompt
        repo_conf_output = wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15)
        if not re.search(repo_config_prompt_regex, repo_conf_output.rstrip()):
             # Make error message clearer about the expected vs actual prompt
             logging.error(f"Expected prompt matching: {repo_config_prompt_regex}")
             logging.error(f"Actual buffer tail received:\n{repo_conf_output[-200:]}") # Log relevant part
             raise RuntimeError(f"Did not get repository config prompt ({repo_config_prompt_regex}).")

        logging.info(f"Sending: url {ftp_url}")
        shell.send(f"url {ftp_url}\n")
        wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15) # Still in repo config

        logging.info(f"Sending: user {ftp_config['username']} password plain {ftp_config['password']}")
        shell.send(f"user {ftp_config['username']} password plain {ftp_config['password']}\n")
        wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15) # Still in repo config

        logging.info("Sending: end")
        shell.send("end\n")
        end_output = wait_for_output(shell, prompt_regex=end_prompt_regex, timeout=15) # Back to normal prompt
        if not re.search(end_prompt_regex, end_output.rstrip()):
             logging.warning(f"Did not get end prompt ({end_prompt_regex}) after 'end'. Got:\n{end_output}")

        shell.close() # Close shell after successful command sequence

    except Exception as e:
        logging.error(f"Exception during repository creation: {e}", exc_info=True)
        print(f"ERROR during repository creation: {e}")
        if shell and shell.active: shell.close()
        return False

    # Verification step (critical after potential prompt issues)
    logging.info("Verifying repository creation...")
    time.sleep(5) # Give ISE a moment
    if check_repository_exists(ssh, repo_name):
        logging.info(f"Repository '{repo_name}' created and verified successfully.")
        print(f"Repository '{repo_name}' created and verified successfully.")
        return True
    else:
        logging.warning("Initial repository check failed, retrying verification in 10s...")
        time.sleep(10)
        if check_repository_exists(ssh, repo_name):
             logging.info(f"Repository '{repo_name}' verified successfully on retry.")
             print(f"Repository '{repo_name}' verified successfully on retry.")
             return True
        else:
             logging.error(f"Repository '{repo_name}' creation failed verification after retry.")
             print(f"ERROR: Repository '{repo_name}' creation failed verification after retry.")
             return False
# --- END CORRECTED create_repository FUNCTION ---

# --- Restore Specific Functions ---

def read_backup_filename_from_file(file_path: str) -> Optional[str]:
    """Reads a backup filename from a specified file."""
    logging.info(f"Attempting to read filename from: {file_path}")
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                filename = f.read().strip()
                if filename:
                    logging.info(f"Successfully read filename '{filename}' from {file_path}")
                    print(f"Read filename '{filename}' from {file_path}")
                    return filename
                else:
                    logging.warning(f"File '{file_path}' exists but is empty.")
                    print(f"WARNING: File '{file_path}' exists but is empty.")
                    return None
        else:
            logging.error(f"Filename file not found: {file_path}")
            print(f"ERROR: Filename file not found: {file_path}")
            return None
    except Exception as e:
        logging.error(f"Error reading filename from {file_path}: {e}", exc_info=True)
        print(f"ERROR: Could not read filename from {file_path}: {e}")
        return None

def reset_application(ssh: paramiko.SSHClient, admin_password: str) -> bool:
    """Performs 'application reset-config ise' with interactive prompts."""
    logging.info("Initiating 'application reset-config ise'...")
    print("Initiating ISE application reset...")
    shell = None
    command = "application reset-config ise"
    cli_prompt = r'\w+/\w+[#>] *$'
    # CORRECTED and more precise prompts dictionary for reset-config
    prompts = {
        # Escape ?, (, ), : and add : at the end. \s* allows for variable spacing.
        r"Initialize your Application configuration to factory defaults\?\s*\(y/n\)\s*:": "y",
        r"Retain existing Application server certificates\?\s*\(y/n\)\s*:": "y", # CRITICAL to retain certs
        # Escape [, ] and add :
        r"Enter the administrator username to create\s*\[admin\]\s*:": "admin", # Assume default 'admin'
        r"Enter the password for 'admin'\s*:": admin_password,
        r"Re-enter the password for 'admin'\s*:": admin_password,
        r"Do you want to continue\?\s*\(y/n\)\s*:": "y"
    }

    try:
        shell = ssh.invoke_shell()
        wait_for_output(shell, prompt_regex=cli_prompt, timeout=20)

        logging.info(f"Sending command: {command}")
        shell.send(command + "\n")
        time.sleep(2) # Short pause after sending command

        # Use monitor_process to handle the interactive sequence and long runtime
        success, output = monitor_process(
            shell=shell,
            completion_pattern="application reset-config is success|Application configuration reset successful", # Look for success message
            error_patterns=["Error:", "failed", "aborted", "reset failed"],
            timeout_minutes=60, # Reset can take a significant amount of time
            interactive_prompts=prompts # Pass corrected prompts
        )

        # Ensure shell is closed after monitor_process finishes or fails
        if shell and shell.active:
            try:
                # Try to wait briefly for final prompt after process completes/fails
                wait_for_output(shell, prompt_regex=cli_prompt, timeout=15)
                shell.close()
                logging.debug("Shell closed after reset monitor.")
            except Exception as close_e:
                 logging.warning(f"Ignoring error while closing shell after reset: {close_e}")

        if success:
            logging.info("Application reset completed successfully.")
            print("\nApplication reset completed successfully.")
            return True
        else:
            logging.error("Application reset process failed or timed out.")
            print("\nERROR: Application reset process failed or timed out.")
            return False

    except Exception as e:
        logging.error(f"Application reset process failed with exception: {e}", exc_info=True)
        print(f"\nERROR during application reset: {e}")
        if shell and shell.active:
            try: shell.close()
            except: pass # Ignore close errors during exception handling
        return False

# --- CORRECTED wait_for_system_ready FUNCTION ---
def wait_for_system_ready(ise_config: Dict[str, str], max_retries: int = 60, retry_interval: int = 90) -> bool:
    """Waits for ISE to become responsive and application running after reset."""
    total_wait_mins = max_retries * retry_interval / 60
    logging.info(f"Waiting for system to become ready post-reset (up to {total_wait_mins:.1f} minutes)")
    print(f"Waiting for system to become ready post-reset (checking every {retry_interval}s, max wait {total_wait_mins:.0f} mins)...")
    hostname = ise_config['hostname']
    cli_prompt_regex = r'\w+/\w+[#>] *$'

    for attempt in range(1, max_retries + 1):
        logging.info(f"Readiness check attempt {attempt}/{max_retries}...")
        print(f"Attempt {attempt}/{max_retries} to connect and check {hostname}...")

        ssh_check = None
        shell = None
        try:
            # Use shorter timeouts for readiness checks
            ssh_check = paramiko.SSHClient()
            ssh_check.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_check.connect(
                hostname,
                username=ise_config['username'],
                password=ise_config['password'],
                timeout=20, # Shorter connection timeout for checks
                banner_timeout=30 # Shorter banner timeout for checks
            )
            logging.info("SSH connection successful. Checking application status via interactive shell...")
            print("SSH connection successful. Checking application status...")

            shell = ssh_check.invoke_shell()
            # Wait for prompt, might take a bit longer if services are starting
            prompt = wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=60)
            if not prompt or not re.search(cli_prompt_regex, prompt.rstrip()):
                 logging.warning("Failed to get initial shell prompt in readiness check.")
                 raise TimeoutError("Failed to get initial shell prompt.")
            logging.info("Initial shell prompt received.")

            # Check application status
            logging.info("Sending 'show application status ise'...")
            shell.send("show application status ise\n")
            # Give status command ample time to run as services initialize
            status_output = wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=180)
            logging.debug(f"'show application status ise' output:\n{status_output}")

            # --- CORRECTED CHECK ---
            lower_status_output = status_output.lower()

            # Check for the actual header start AND 'running' state (case-insensitive)
            # Using "ise process name" which is the correct start of the header
            if "ise process name" in lower_status_output and "running" in lower_status_output:
                logging.info("ISE application status header found and 'running' state detected.")
                # Optional: Add more specific checks for essential services if needed
                # if "application server" in lower_status_output and "database server" in lower_status_output: ...
                print("\nISE system is ready.")
                return True # System is ready!
            # --- END CORRECTED CHECK ---
            else:
                # Log current state if not ready based on the new check
                # Basic check if the command output seems valid but doesn't meet ready criteria
                if "ise process name" not in lower_status_output and "error" not in lower_status_output and "invalid" not in lower_status_output:
                    logging.warning("Output from 'show application status ise' does not contain expected header 'ise process name'.")
                    print("Command output format unexpected or incomplete.")
                    # Continue retrying, maybe services aren't fully up yet
                elif "initializing" in lower_status_output:
                    logging.info("Application status is INITIALIZING.")
                    print("Application status: INITIALIZING...")
                elif "disabled" in lower_status_output and "running" not in lower_status_output:
                    # If only disabled services are listed and no 'running'
                    logging.info("Application status shows only disabled services or is not running.")
                    print("Application status: Not Running / Only Disabled...")
                else:
                    # General case if not running and not initializing
                    logging.warning(f"Application status indeterminate or not yet running based on corrected check. Status Output tail: {status_output.strip()[-300:]}")
                    print("Application status indeterminate or not yet running.")


        except paramiko.AuthenticationException as auth_e:
            logging.error(f"Authentication failed during readiness check (Attempt {attempt}): {auth_e}. Check password/reset state.")
            print(f"ERROR: Authentication failed (Attempt {attempt}). Reset may have failed.")
            return False # Treat auth failure post-reset as fatal for readiness
        except Exception as e:
            # Log non-critical errors as warnings during polling
            log_level = logging.WARNING if isinstance(e, (paramiko.SSHException, TimeoutError, ConnectionRefusedError, OSError)) else logging.ERROR
            logging.log(log_level, f"Readiness check attempt {attempt} failed: {type(e).__name__} - {e}", exc_info=False)
            print(f"System not ready yet (Attempt {attempt}): {type(e).__name__}")
        finally:
             # Ensure connections/shells are closed
             if shell and shell.active:
                 try: shell.close()
                 except: pass
             if ssh_check and ssh_check.get_transport() and ssh_check.get_transport().is_active():
                 try: ssh_check.close()
                 except: pass

        # Wait before the next attempt if not max retries
        if attempt < max_retries:
            logging.info(f"Waiting {retry_interval} seconds before next check.")
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)
        else:
             logging.error(f"System readiness check failed after {max_retries} attempts.")
             print(f"\nERROR: Failed readiness check after {max_retries} attempts.")

    # If loop completes without returning True
    logging.error("System did not become ready within the expected time after exhausting retries.")
    print("ERROR: System did not become ready within the expected time.")
    return False
# --- END CORRECTED wait_for_system_ready FUNCTION ---

def restore_backup(ssh: paramiko.SSHClient, repo_name: str, backup_filename: str, backup_config: Dict[str, str]) -> bool:
    """Restore configuration backup from the specified file using 'restore' command."""
    logging.info(f"Initiating restore from configuration file: {backup_filename}")
    print(f"Initiating restore from configuration file: {backup_filename}")
    encryption_key = backup_config['encryption_key']
    command = f"restore {backup_filename} repository {repo_name} encryption-key plain {encryption_key}"
    shell = None
    cli_prompt = r'\w+/\w+[#>] *$'
    # Prompt for restore confirmation (corrected regex)
    prompts = { r"Do you want to continue with restore\?\s*\(y/n\)\s*:": "y" }

    try:
        shell = ssh.invoke_shell()
        wait_for_output(shell, prompt_regex=cli_prompt, timeout=20)

        logging.info(f"Sending restore command: {command}")
        shell.send(command + "\n")
        time.sleep(2)

        # Monitor the long restore process
        success, output = monitor_process(
            shell=shell,
            completion_pattern=r"100% completed|Restore successful|Restore Completed Successfully", # Look for success messages
            error_patterns=["Error:", "failed", "aborted", "Unable to restore", "Repository not accessible", "restore failed"],
            timeout_minutes=120, # Restore can take a very long time
            interactive_prompts=prompts
        )

        if shell and shell.active:
             # Wait for prompt after restore finishes/fails
             wait_for_output(shell, prompt_regex=cli_prompt, timeout=30)
             shell.close()

        if success:
            logging.info("Configuration restore completed successfully.")
            print("\nConfiguration restore completed successfully.")
            return True
        else:
            logging.error("Configuration restore process failed or timed out.")
            print("\nERROR: Configuration restore process failed or timed out.")
            return False

    except Exception as e:
        logging.error(f"Configuration restore process failed with exception: {e}", exc_info=True)
        print(f"\nERROR during configuration restore: {e}")
        if shell and shell.active:
             try: shell.close()
             except: pass
        return False

def import_ca_key_pairs(ssh: paramiko.SSHClient, repo_name: str, backup_config: Dict[str, str]) -> bool:
    """
    Import ISE CA Key Pairs using menu option 8.
    Reads the filename to import from backup_config['ca_keys_fixed_filename'].
    """
    # Get filename and key from the backup_config dictionary
    ca_keys_filename_to_import = backup_config['ca_keys_fixed_filename']
    encryption_key = backup_config['encryption_key']

    logging.info(f"Initiating import of CA Key Pairs using filename from config: {ca_keys_filename_to_import}")
    print(f"Initiating import of CA Key Pairs from: {ca_keys_filename_to_import}")

    shell = None
    cli_prompt_regex = r'\w+/\w+[#>] *$'
    # Use more robust menu prompt detection looking for [0]Exit at end of line
    menu_prompt_regex = r'\[0\]\s*Exit\s*$'
    # Prompts specific to Import (option 8) - corrected regexes
    repo_prompt_regex = r'Import Repository Name\s*:\s*' # Added colon and optional space
    filename_prompt_regex = r'Enter CA keys file name to import\s*:\s*' # Added colon and optional space
    key_prompt_regex = r'Enter encryption-key\s*:\s*' # Added colon and optional space
    completion_regex = r'CA key pairs imported successfully'
    error_patterns = ["Error:", "failed", "Unable to import", "Repository not accessible", "Invalid encryption key", "File not found"]

    try:
        shell = ssh.invoke_shell()
        initial_prompt = wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=20)
        if not re.search(cli_prompt_regex, initial_prompt.rstrip()):
            logging.warning(f"Did not receive expected initial prompt ({cli_prompt_regex}) before 'app configure'.")

        logging.info("Sending: application configure ise")
        shell.send("application configure ise\n")
        # Wait for the main menu prompt ([0]Exit)
        menu_output = wait_for_output(shell, prompt_regex=menu_prompt_regex, timeout=45)
        if not re.search(menu_prompt_regex, menu_output.rstrip()):
            raise RuntimeError(f"Failed to get 'application configure ise' main menu prompt ({menu_prompt_regex}). Got buffer tail:\n{menu_output[-500:]}")

        logging.info("Sending: 8 (Import Internal CA Store)")
        shell.send("8\n")
        repo_prompt_output = wait_for_output(shell, prompt_regex=repo_prompt_regex, timeout=30)
        if not re.search(repo_prompt_regex, repo_prompt_output):
             raise RuntimeError(f"Import Repository name prompt ({repo_prompt_regex}) not found after sending 8. Got:\n{repo_prompt_output}")

        logging.info(f"Sending repository name: {repo_name}")
        shell.send(f"{repo_name}\n")

        # Wait for the filename prompt specific to import
        filename_prompt_output = wait_for_output(shell, prompt_regex=filename_prompt_regex, timeout=30)
        if not re.search(filename_prompt_regex, filename_prompt_output):
             raise RuntimeError(f"CA keys import filename prompt ({filename_prompt_regex}) not found. Got:\n{filename_prompt_output}")

        # *** Send the filename read from backup_config ***
        logging.info(f"Sending import filename (from config): {ca_keys_filename_to_import}")
        shell.send(f"{ca_keys_filename_to_import}\n")
        # ************************************************

        key_prompt_output = wait_for_output(shell, prompt_regex=key_prompt_regex, timeout=30)
        if not re.search(key_prompt_regex, key_prompt_output):
             raise RuntimeError(f"Encryption key prompt ({key_prompt_regex}) not found for import. Got:\n{key_prompt_output}")

        logging.info("Sending encryption key (password)")
        shell.send(f"{encryption_key}\n")

        # Monitor the import process
        success, output = monitor_process(
            shell,
            completion_pattern=completion_regex,
            error_patterns=error_patterns,
            timeout_minutes=30 # Import might be faster than export/restore
        )

        # Attempt to exit menus cleanly
        logging.info("Attempting to exit menus...")
        menu_exit_success = False
        if shell and shell.active:
            try:
                # Expect menu prompt after import attempt
                wait_for_output(shell, prompt_regex=menu_prompt_regex, timeout=15) # Use correct menu regex
                logging.debug("Sending '0' to exit current menu level (8)")
                shell.send("0\n")
                time.sleep(2)
                wait_for_output(shell, prompt_regex=menu_prompt_regex, timeout=15) # Use correct menu regex
                logging.debug("Sending '0' to exit main app configure menu")
                shell.send("0\n")
                time.sleep(2)
                wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=15)
                logging.info("Exited menus successfully.")
                menu_exit_success = True
            except Exception as exit_e:
                 logging.warning(f"Could not cleanly exit menus: {exit_e}", exc_info=False)
            finally:
                 # Ensure shell is closed after attempts
                 if shell and shell.active:
                     logging.debug("Closing shell after menu operations.")
                     shell.close()
                     shell = None
        else:
             logging.warning("Shell was not active after monitor_process for import, cannot attempt menu exit.")

        if success:
            logging.info("CA Key Pairs import successful.")
            print("\nCA Key Pairs import successful.")
            return True
        else:
            logging.error("CA Key Pairs import failed or timed out.")
            print("\nERROR: CA Key Pairs import failed or timed out.")
            # Log relevant part of output for debugging
            logging.error(f"Final output before import failure:\n{output[-500:]}")
            return False

    except Exception as e:
        logging.error(f"CA Key Pairs import process failed with exception: {e}", exc_info=True)
        print(f"\nERROR during CA Key Pairs import: {e}")
        if shell and shell.active:
             try: shell.close()
             except: pass
        return False

def verify_ise_functionality(ssh: paramiko.SSHClient) -> bool:
    """Verify basic ISE functionality after restore using 'show application status ise'."""
    logging.info("Verifying ISE functionality post-restore...")
    print("Verifying ISE functionality post-restore...")
    try:
        # Check application status again using execute_interactive_commands
        app_commands = ["show application status ise"]
        # Allow more time for status check post-restore
        app_success, app_output = execute_interactive_commands(ssh, app_commands, timeout=120)

        if not app_success:
             logging.error(f"Command 'show application status ise' failed during verification.")
             print("ERROR: Command 'show application status ise' failed during verification.")
             return False

        # --- CORRECTED CHECK (Same logic as wait_for_system_ready) ---
        lower_app_output = app_output.lower()
        if "ise process name" in lower_app_output and "running" in lower_app_output:
            logging.info("ISE application status header found and 'running' state detected during verification.")
            print("ISE application is running.")
            logging.info("Basic ISE functionality verification passed.")
            print("Basic ISE functionality verification passed.")
            return True
        # --- END CORRECTED CHECK ---
        else:
            logging.error(f"ISE application status check shows not running post-restore. Output:\n{app_output}")
            print("ERROR: ISE application is NOT running after restore and import.")
            return False

    except Exception as e:
        logging.error(f"Error during ISE functionality verification: {e}", exc_info=True)
        print(f"Error during ISE functionality verification: {e}")
        return False

# --- Main Execution Logic ---

def main():
    """Main function for the restore script."""
    start_time = time.time()
    logging.info("--- Starting ISE Restore Script ---")
    ssh_pre_reset = None # Connection for initiating reset
    ssh = None # Connection used after reset

    try:
        # Read configurations
        ise_config, ftp_config, backup_config = read_config()
        # Read the specific config backup filename saved by the backup script
        config_backup_filename = read_backup_filename_from_file(CONFIG_FILENAME_STORE)
        # CA keys filename is now read from config.xml into backup_config['ca_keys_fixed_filename']
        ca_keys_backup_filename = backup_config['ca_keys_fixed_filename'] # Get it for logging

        if not config_backup_filename:
            sys.exit(f"FATAL: Configuration backup filename not found in {CONFIG_FILENAME_STORE}. Cannot proceed.")
        # No need to check/read CERT_KEYS_FILENAME_STORE

        # Log filenames being used
        logging.info(f"Using Configuration Backup file: {config_backup_filename}")
        logging.info(f"Using CA Keys Backup file (from config.xml): {ca_keys_backup_filename}")
        print(f"Attempting restore using:")
        print(f"  - Config Backup: {config_backup_filename}")
        print(f"  - CA Keys Backup: {ca_keys_backup_filename} (from config.xml)")


        # --- Step 1: Connect and Reset ---
        print("\n--- Step 1: Connecting to ISE and Initiating Reset ---")
        ssh_pre_reset = ssh_connect(ise_config)
        if not ssh_pre_reset:
            raise RuntimeError("Failed to establish initial SSH connection for reset.")

        if not reset_application(ssh_pre_reset, ise_config['password']):
            # Ensure connection is closed even if reset fails partially
            if ssh_pre_reset and ssh_pre_reset.get_transport() and ssh_pre_reset.get_transport().is_active():
                try: ssh_pre_reset.close()
                except: pass
            raise RuntimeError("Application reset process failed or timed out.")

        logging.info("Closing SSH connection used for reset command.")
        ssh_pre_reset.close()
        ssh_pre_reset = None # Ensure it's marked as closed


        # --- Step 2: Wait for System Readiness ---
        print("\n--- Step 2: Waiting for ISE System to Become Ready Post-Reset ---")
        if not wait_for_system_ready(ise_config): # Use the corrected function
            raise RuntimeError("System did not become ready after reset within the timeout period.")


        # --- Step 3: Reconnect and Prepare Repository ---
        print("\n--- Step 3: Reconnecting to ISE Post-Reset ---")
        # Use multiple retries for post-reset connection as services might still be starting
        ssh = ssh_connect(ise_config, max_retries=5, retry_delay=30)
        if not ssh:
            raise RuntimeError("Failed to establish SSH connection after system reset and retries.")

        logging.info("Checking/Creating repository post-reset...")
        print("Checking/Creating repository post-reset...")
        if not check_repository_exists(ssh, DEFAULT_REPO_NAME):
            # Use the corrected function
            if not create_repository(ssh, DEFAULT_REPO_NAME, ftp_config):
                raise RuntimeError(f"Failed to create repository '{DEFAULT_REPO_NAME}' after reset.")
        else:
            logging.info(f"Repository '{DEFAULT_REPO_NAME}' exists after reset.")


        # --- Step 4: Restore Main Configuration ---
        print(f"\n--- Step 4: Restoring Configuration from {config_backup_filename} ---")
        if not restore_backup(ssh, DEFAULT_REPO_NAME, config_backup_filename, backup_config):
            raise RuntimeError("Configuration restore process failed or timed out.")

        # Wait for services to potentially restart after main restore
        wait_after_restore = 180 # 3 minutes
        logging.info(f"Waiting {wait_after_restore} seconds after configuration restore for services...")
        print(f"Waiting {wait_after_restore} seconds after configuration restore...")
        time.sleep(wait_after_restore)


        # --- Step 5: Import CA Key Pairs ---
        print(f"\n--- Step 5: Importing CA Key Pairs from {ca_keys_backup_filename} ---")
        # Pass the full backup_config dict which contains the filename and key
        if not import_ca_key_pairs(ssh, DEFAULT_REPO_NAME, backup_config):
            raise RuntimeError("CA Key Pairs import failed or timed out. Restore incomplete.")

        logging.info("CA Key Pairs import reported success.")
        print("\nCA Key Pairs import reported success.")
        # Wait after CA import for changes to apply
        wait_after_cert_import = 90 # 1.5 minutes
        logging.info(f"Waiting {wait_after_cert_import} seconds after CA keys import...")
        print(f"Waiting {wait_after_cert_import} seconds after CA keys import...")
        time.sleep(wait_after_cert_import)


        # --- Step 6: Verify Functionality ---
        print("\n--- Step 6: Verifying ISE Functionality ---")
        # Reconnect for verification for robustness
        logging.info("Closing connection before final verification.")
        if ssh and ssh.get_transport() and ssh.get_transport().is_active():
            ssh.close()
            ssh = None # Mark as closed
        time.sleep(10) # Brief pause before reconnecting
        logging.info("Reconnecting for final verification.")
        ssh = ssh_connect(ise_config, max_retries=3, retry_delay=15)
        if not ssh:
             logging.error("Failed to reconnect for final verification step.")
             # Treat as verification failure
             verify_success = False
        else:
             # Use the corrected verification function
             verify_success = verify_ise_functionality(ssh)


        # --- Final Outcome ---
        elapsed_time = time.time() - start_time
        if verify_success:
            logging.info(f"--- ISE Restore Script Completed Successfully in {elapsed_time:.2f} seconds ---")
            print("\n======================================================")
            print(f" RESTORE PROCESS COMPLETED SUCCESSFULLY ({elapsed_time:.2f}s)")
            print("======================================================")
            print("  Initial verification passed.")
            print("======================================================")
        else:
            logging.error(f"--- ISE Restore Completed in {elapsed_time:.2f} seconds, BUT VERIFICATION FAILED ---")
            print("\n======================================================")
            print(f" ERROR: RESTORE PROCESS COMPLETED BUT VERIFICATION FAILED ({elapsed_time:.2f}s)")
            print("======================================================")
            print("  Manual investigation required. Check application status and logs.")
            print("======================================================")
            sys.exit(2) # Exit with a specific code for verification failure

    except Exception as e:
        elapsed_time = time.time() - start_time
        logging.critical(f"Restore script failed after {elapsed_time:.2f} seconds: {e}", exc_info=True)
        print(f"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f" FATAL ERROR: Restore script failed after {elapsed_time:.2f} seconds.")
        print(f" Error: {e}")
        print(f" Check log file '{LOG_FILE}' for details.")
        print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        sys.exit(1) # Exit with general error code
    finally:
        # Ensure connections are closed if they were successfully opened
        if ssh_pre_reset and ssh_pre_reset.get_transport() and ssh_pre_reset.get_transport().is_active():
             logging.info("Closing pre-reset SSH connection in finally block.")
             try: ssh_pre_reset.close()
             except: pass
        if ssh and ssh.get_transport() and ssh.get_transport().is_active():
            logging.info("Closing final SSH connection in finally block.")
            print("Closing final SSH connection.")
            try: ssh.close()
            except: pass
        logging.info("--- Restore script finished ---")

if __name__ == '__main__':
    main()