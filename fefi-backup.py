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
LOG_FILE = 'ise-backup-log.txt'
CERT_KEYS_FILENAME_STORE = 'cert_keys_backup_filename.txt' # For CA Keys backup filename
CONFIG_FILENAME_STORE = 'backup_filename.txt'
DEFAULT_REPO_NAME = "FTP-Repo"
# REMOVED FIXED_CA_KEYS_FILENAME constant - will be read from config

# --- Logging Setup ---
# (Same as previous version - with filemode='w')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filemode='w' # Start with a fresh log each time
)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)
logging.getLogger("paramiko").setLevel(logging.WARNING)


# --- Helper Functions ---
# ssh_connect, wait_for_output, monitor_process
# execute_interactive_commands, check_repository_exists, create_repository
# initiate_backup
# (Identical helper functions from previous version)

def read_config() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Reads config.xml, including the fixed CA keys filename."""
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
                # ADDED ca_keys_fixed_filename as required for backup section
                'backup': ['name', 'encryption_key', 'ca_keys_fixed_filename']
            }
            if section_name in required:
                 for key in required[section_name]:
                     # Ensure key exists and is not empty/whitespace only
                     if key not in conf or not conf[key] or not conf[key].strip():
                         raise ValueError(f"Missing or empty value for '{key}' in '{section_name}' section")
            return conf

        ise_config = extract_config(ise, 'ise')
        ftp_config = extract_config(ftp, 'ftp')
        backup_config = extract_config(backup, 'backup') # Now includes ca_keys_fixed_filename

        # Validate encryption key format
        key = backup_config.get('encryption_key', '')
        if len(key) < 8 or not any(char.isdigit() for char in key):
            raise ValueError("Backup encryption key must be >= 8 chars and include a digit.")

        logging.info("Configuration read successfully.")
        # Log the fixed filename read from config
        logging.debug(f"Using fixed CA keys filename from config: {backup_config['ca_keys_fixed_filename']}")
        return ise_config, ftp_config, backup_config

    except ET.ParseError as e:
        logging.critical(f"FATAL: Error parsing {CONFIG_FILE}: {e}", exc_info=True)
        sys.exit(f"FATAL: Error parsing {CONFIG_FILE}: {e}")
    except ValueError as e: # Catch validation errors
        logging.critical(f"FATAL: Configuration validation error: {e}", exc_info=True)
        sys.exit(f"FATAL: Configuration validation error: {e}")
    except Exception as e:
        logging.critical(f"FATAL: Error reading configuration: {e}", exc_info=True)
        sys.exit(f"FATAL: Error reading configuration: {e}")

def ssh_connect(ise_config: Dict[str, str], max_retries: int = 3, retry_delay: int = 20) -> Optional[paramiko.SSHClient]:
    # (Identical to previous version)
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
                timeout=30,
                banner_timeout=45
            )
            logging.info(f"SSH connection to {hostname} established successfully.")
            return ssh
        except paramiko.AuthenticationException:
            logging.critical(f"Authentication failed for {ise_config['username']}@{hostname}.")
            if ssh: ssh.close()
            return None
        except Exception as e:
            logging.warning(f"SSH connection attempt {attempt}/{max_retries} to {hostname} failed: {type(e).__name__} - {e}", exc_info=False)
            if ssh: ssh.close()
            if attempt < max_retries:
                logging.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logging.critical(f"All SSH connection attempts to {hostname} failed.")
                return None
    return None

def wait_for_output(shell: paramiko.Channel, prompt_regex: str = r'[#>]\s*$', timeout: int = 30, interval: float = 0.5) -> str:
    # (Identical to previous version)
    start_time = time.time()
    buffer = ""
    logging.debug(f"Waiting for output (prompt: '{prompt_regex}', timeout: {timeout}s)")
    while time.time() - start_time < timeout:
        if shell.recv_ready():
            try:
                chunk = shell.recv(8192).decode("utf-8", errors='ignore')
                logging.debug(f"Received chunk: {chunk.strip()}")
                buffer += chunk
                if chunk:
                    start_time = time.time()
            except Exception as e:
                 logging.warning(f"Error receiving data from shell: {e}")
                 time.sleep(interval)
                 continue

        stripped_buffer = buffer.rstrip()
        if re.search(f"{prompt_regex}$", stripped_buffer):
             logging.debug(f"Prompt '{prompt_regex}' detected at end of stripped buffer.")
             break
        elif re.search(prompt_regex, buffer[-500:]):
             logging.debug(f"Prompt '{prompt_regex}' detected within last 500 chars.")
             break

        if time.time() - start_time >= timeout:
            logging.warning(f"Timeout reached waiting for output matching prompt '{prompt_regex}'")
            break

        time.sleep(interval)

    logging.debug(f"wait_for_output returning buffer (len={len(buffer)}):\n{buffer[-500:]}")
    return buffer


def monitor_process(shell: paramiko.Channel, completion_pattern: str, error_patterns: List[str], timeout_minutes: int = 30, progress_interval: int = 10, interactive_prompts: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    # (Identical to previous version)
    completion_regex = re.compile(completion_pattern, re.IGNORECASE)
    error_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in error_patterns]
    prompt_regexes = {}
    if interactive_prompts:
        prompt_regexes = {re.compile(p, re.IGNORECASE | re.DOTALL): r for p, r in interactive_prompts.items()}

    logging.info(f"Monitoring process for completion '{completion_regex.pattern}' (Timeout: {timeout_minutes} mins)")

    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    full_output = ""
    last_progress_time = time.time()
    responded_prompts = set()

    while time.time() - start_time < timeout_seconds:
        received_data = False
        latest_chunk = ""
        if shell.recv_ready():
            try:
                latest_chunk = shell.recv(8192).decode("utf-8", errors='ignore')
                if latest_chunk:
                    received_data = True
                    full_output += latest_chunk
                    print(latest_chunk, end='', flush=True)
                    logging.debug(f"Process output chunk: {latest_chunk.strip()}")
                    last_progress_time = time.time()
            except Exception as e:
                logging.warning(f"Exception reading from shell during monitor: {e}")

        if completion_regex.search(full_output):
            logging.info("Process completed successfully (completion pattern found).")
            print("\nProcess completed successfully.")
            return True, full_output

        check_string = latest_chunk if received_data else full_output[-1024:]
        for err_regex in error_regexes:
            if err_regex.search(check_string):
                logging.error(f"Error pattern '{err_regex.pattern}' detected.")
                print(f"\nERROR pattern '{err_regex.pattern}' detected.")
                return False, full_output

        if prompt_regexes and received_data:
            buffer_end = full_output[-512:]
            for prompt_re, response in prompt_regexes.items():
                match = prompt_re.search(buffer_end)
                prompt_key = prompt_re.pattern
                if match and prompt_key not in responded_prompts:
                    logging.info(f"Detected prompt '{prompt_key}'. Sending response '{response}'.")
                    print(f"\nResponding '{response}'...")
                    try:
                        shell.send(response + "\n")
                        responded_prompts.add(prompt_key)
                        time.sleep(2)
                    except Exception as send_e:
                         logging.error(f"Failed to send response to prompt '{prompt_key}': {send_e}")
                         return False, full_output
                    break

        if not received_data:
             time.sleep(1)

        if time.time() - last_progress_time > progress_interval * 60:
            logging.warning(f"No output received for {progress_interval} minutes.")
            print(f"\nWarning: No output received for {progress_interval} minutes.")
            last_progress_time = time.time()

        if not shell.active:
             logging.error("Shell became inactive during monitored process.")
             print("\nERROR: Shell connection lost.")
             return False, full_output

    logging.error(f"Process timed out after {timeout_minutes} minutes waiting for '{completion_regex.pattern}'.")
    print(f"\nERROR: Process timed out after {timeout_minutes} minutes.")
    return False, full_output

def execute_interactive_commands(ssh: paramiko.SSHClient, commands: List[str], timeout: int = 45, prompt_regex: Optional[str] = None) -> Tuple[bool, str]:
    # (Identical to previous version)
    if prompt_regex is None:
        prompt_regex = r'\w+/\w+[#>] *$'
    logging.info(f"Executing interactive commands: {commands} (prompt: {prompt_regex})")
    full_output = ""
    shell = None
    try:
        shell = ssh.invoke_shell()
        output_buffer = wait_for_output(shell, prompt_regex=prompt_regex, timeout=30)
        full_output += output_buffer
        if not re.search(prompt_regex, output_buffer.rstrip()):
            logging.warning(f"Did not receive expected initial prompt matching '{prompt_regex}'. Output buffer tail:\n{output_buffer[-500:]}")
        logging.debug(f"Initial shell output handled (len={len(output_buffer)}).")

        for command in commands:
            logging.info(f"Sending command: {command}")
            print(f"Executing: {command}")
            shell.send(command + "\n")
            output = wait_for_output(shell, prompt_regex=prompt_regex, timeout=timeout)
            full_output += output
            new_output = output
            cmd_echo_pos = output.rfind(command)
            if cmd_echo_pos != -1:
                 start_pos = cmd_echo_pos + len(command) + 1
                 prompt_match = re.search(prompt_regex, output[start_pos:])
                 if prompt_match:
                      new_output = output[start_pos : start_pos + prompt_match.start()]
                 else:
                      new_output = output[start_pos:]

            logging.info(f"Output for '{command}':\n{new_output.strip()}")
            print(f"Output:\n{new_output.strip()}")

            lower_new_output = new_output.lower()
            if "% invalid" in lower_new_output or \
               "syntax error" in lower_new_output or \
               "error:" in lower_new_output or \
               "fail" in lower_new_output or \
               "aborted" in lower_new_output or \
               "repository not found" in lower_new_output:
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
    # (Identical to previous version)
    logging.info(f"Checking if repository '{repo_name}' exists...")
    commands = [f"show repository {repo_name}"]
    prompt_regex = r'\w+/\w+[#>] *$'
    success, output = execute_interactive_commands(ssh, commands, timeout=75, prompt_regex=prompt_regex)
    exists = success and "% Repository not found" not in output
    logging.info(f"Repository '{repo_name}' {'exists' if exists else 'does not exist'}.")
    print(f"Repository '{repo_name}' {'exists' if exists else 'does not exist'}.")
    return exists

def create_repository(ssh: paramiko.SSHClient, repo_name: str, ftp_config: Dict[str, str]) -> bool:
    # (Identical to previous version)
    logging.info(f"Creating repository '{repo_name}'...")
    print(f"Creating repository '{repo_name}'...")
    ftp_url = f"ftp://{ftp_config['hostname']}/{ftp_config['backup_dir']}"
    config_prompt_regex = r'\w+\(config\)#[ ]*$'
    repo_config_prompt_regex = r'\w+\(config-Repository\)#[ ]*$'
    end_prompt_regex = r'\w+/\w+[#>] *$'

    shell = None
    try:
        shell = ssh.invoke_shell()
        initial_output = wait_for_output(shell, prompt_regex=end_prompt_regex, timeout=20)
        if not re.search(end_prompt_regex, initial_output.rstrip()):
             logging.warning("Did not get expected initial prompt before configure terminal.")

        logging.info("Sending: configure terminal")
        shell.send("configure terminal\n")
        conf_output = wait_for_output(shell, prompt_regex=config_prompt_regex, timeout=15)
        if not re.search(config_prompt_regex, conf_output.rstrip()):
             raise RuntimeError(f"Did not get config prompt ({config_prompt_regex}). Got:\n{conf_output}")


        logging.info(f"Sending: repository {repo_name}")
        shell.send(f"repository {repo_name}\n")
        repo_conf_output = wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15)
        if not re.search(repo_config_prompt_regex, repo_conf_output.rstrip()):
             raise RuntimeError(f"Did not get repository config prompt ({repo_config_prompt_regex}). Got:\n{repo_conf_output}")


        logging.info(f"Sending: url {ftp_url}")
        shell.send(f"url {ftp_url}\n")
        wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15)

        logging.info(f"Sending: user {ftp_config['username']} password plain {ftp_config['password']}")
        shell.send(f"user {ftp_config['username']} password plain {ftp_config['password']}\n")
        wait_for_output(shell, prompt_regex=repo_config_prompt_regex, timeout=15)

        logging.info("Sending: end")
        shell.send("end\n")
        end_output = wait_for_output(shell, prompt_regex=end_prompt_regex, timeout=15)
        if not re.search(end_prompt_regex, end_output.rstrip()):
             raise RuntimeError(f"Did not get end prompt ({end_prompt_regex}). Got:\n{end_output}")


        shell.close()

    except Exception as e:
        logging.error(f"Exception during repository creation: {e}", exc_info=True)
        print(f"ERROR during repository creation: {e}")
        if shell and shell.active: shell.close()
        return False

    # Verification step
    logging.info("Verifying repository creation...")
    time.sleep(5)
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

def initiate_backup(ssh: paramiko.SSHClient, backup_config: Dict[str, str], repo_name: str) -> Optional[str]:
    # (Identical to previous version - uses backup_config['name'] for base name)
    backup_base_name = backup_config['name']
    encryption_key = backup_config['encryption_key']
    logging.info(f"Initiating configuration backup '{backup_base_name}'...")
    print(f"Initiating configuration backup '{backup_base_name}'...")
    shell = None
    command = f"backup {backup_base_name} repository {repo_name} ise-config encryption-key plain {encryption_key}"
    prompt_regex = r'\w+/\w+[#>] *$'

    try:
        shell = ssh.invoke_shell()
        wait_for_output(shell, prompt_regex=prompt_regex, timeout=20)

        logging.info(f"Sending backup command: {command}")
        shell.send(command + "\n")

        success, output = monitor_process(
            shell,
            completion_pattern=r"100% completed|Backup successful",
            error_patterns=["Error:", "failed", "aborted", "Repository not accessible", "Invalid encryption key", "Unable to backup"],
            timeout_minutes=90
        )

        wait_for_output(shell, prompt_regex=prompt_regex, timeout=15)
        if shell and shell.active: shell.close()

        if success:
            match = re.search(r'% Creating backup with timestamped filename:\s*(\S+)', output, re.IGNORECASE)
            if match:
                backup_filename = match.group(1).strip()
                logging.info(f"Configuration backup successful. Filename: {backup_filename}")
                print(f"\nConfiguration backup successful. Filename: {backup_filename}")
                try:
                    with open(CONFIG_FILENAME_STORE, "w") as f: f.write(backup_filename)
                    logging.info(f"Configuration backup filename saved to {CONFIG_FILENAME_STORE}")
                except Exception as write_e:
                     logging.error(f"Failed to write config backup filename to {CONFIG_FILENAME_STORE}: {write_e}")
                return backup_filename
            else:
                logging.warning("Backup reported success, but couldn't extract exact filename from output.")
                print("\nWARNING: Backup successful, but couldn't extract exact filename. Check logs/FTP.")
                try:
                    placeholder = f"{backup_base_name}-UnknownTimestamp-{datetime.now():%Y%m%d%H%M}"
                    with open(CONFIG_FILENAME_STORE, "w") as f: f.write(placeholder)
                except: pass
                return placeholder
        else:
            logging.error("Configuration backup process failed or timed out.")
            print("\nERROR: Configuration backup process failed or timed out.")
            return None

    except Exception as e:
        logging.error(f"Configuration backup process failed with exception: {e}", exc_info=True)
        print(f"\nERROR during configuration backup: {e}")
        if shell and shell.active: shell.close()
        return None

# --- REVISED CA Keys Backup Function (Reads fixed name from backup_config) ---

def backup_ca_key_pairs(ssh: paramiko.SSHClient, repo_name: str, backup_config: Dict[str, str]) -> Optional[str]:
    """
    Backup ISE CA Key Pairs using fixed filename read from backup_config.
    Does NOT discover or verify the filename after export.
    """
    # Get fixed filename and encryption key from the passed config dictionary
    fixed_ca_filename = backup_config['ca_keys_fixed_filename']
    encryption_key = backup_config['encryption_key']

    logging.info("Initiating CA Key Pairs backup via 'application configure ise' menu...")
    logging.info(f"Using fixed output filename from config: {fixed_ca_filename}")
    print(f"Initiating CA Key Pairs backup (using fixed filename: {fixed_ca_filename})...")

    shell = None
    cli_prompt_regex = r'\w+/\w+[#>] *$'
    menu_prompt_regex = r'\[0\]\s*Exit\s*$'
    repo_prompt_regex = r'Export Repository Name:\s*'
    key_prompt_regex = r'Enter encryption-key for export:\s*'
    completion_regex = r'ISE CA keys export completed successfully'
    # More specific pattern to avoid matching the filename itself if it contains "export"
    # completion_regex = r'ISE CA keys export completed successfully.*\[0\]\s*Exit' # Check if prompt follows completion
    error_patterns = ["Error:", "failed", "Unable to export", "Repository not accessible", "Invalid encryption key"]

    try:
        shell = ssh.invoke_shell()
        initial_prompt = wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=20)
        if not re.search(cli_prompt_regex, initial_prompt.rstrip()):
            logging.warning(f"Did not receive expected initial prompt ({cli_prompt_regex}) before 'app configure'.")

        logging.info("Sending: application configure ise")
        shell.send("application configure ise\n")
        menu_output = wait_for_output(shell, prompt_regex=menu_prompt_regex, timeout=45)
        if not re.search(menu_prompt_regex, menu_output.rstrip()):
            raise RuntimeError(f"Failed to get 'application configure ise' main menu prompt ({menu_prompt_regex}). Got buffer tail:\n{menu_output[-500:]}")

        logging.info("Sending: 7 (Export Internal CA Store)")
        shell.send("7\n")
        repo_prompt_output = wait_for_output(shell, prompt_regex=repo_prompt_regex, timeout=30)
        if not re.search(repo_prompt_regex, repo_prompt_output):
             raise RuntimeError(f"Repository name prompt ({repo_prompt_regex}) not found after sending 7. Got:\n{repo_prompt_output}")

        logging.info(f"Sending repository name: {repo_name}")
        shell.send(f"{repo_name}\n")

        key_prompt_output = wait_for_output(shell, prompt_regex=key_prompt_regex, timeout=30)
        if not re.search(key_prompt_regex, key_prompt_output):
             raise RuntimeError(f"Encryption key prompt ({key_prompt_regex}) not found. Got:\n{key_prompt_output}")

        logging.info("Sending encryption key (password)")
        shell.send(f"{encryption_key}\n")

        # Monitor the export process
        success, output = monitor_process(
            shell,
            completion_pattern=completion_regex,
            error_patterns=error_patterns,
            timeout_minutes=30
        )

        # --- Attempt to exit menus cleanly AFTER monitor_process ---
        logging.info("Attempting to exit menus...")
        menu_exit_success = False
        if shell and shell.active:
            try:
                logging.debug("Sending '0' to exit current menu level (7)")
                shell.send("0\n")
                time.sleep(2)

                wait_for_output(shell, prompt_regex=menu_prompt_regex, timeout=15)
                logging.debug("Sending '0' to exit main app configure menu")
                shell.send("0\n")
                time.sleep(2)

                wait_for_output(shell, prompt_regex=cli_prompt_regex, timeout=15)
                logging.info("Exited menus successfully.")
                menu_exit_success = True
            except Exception as exit_e:
                 logging.warning(f"Could not cleanly exit menus: {exit_e}", exc_info=False)
            finally:
                 if shell and shell.active:
                     logging.debug("Closing shell after menu operations.")
                     shell.close()
                     shell = None
        else:
             logging.warning("Shell was not active after monitor_process, cannot attempt menu exit.")

        # --- Process results ---
        if success:
            logging.info(f"CA Key Pairs export reported success. Using fixed filename from config: {fixed_ca_filename}")
            print(f"\nCA Key Pairs export reported success.")
            try:
                with open(CERT_KEYS_FILENAME_STORE, "w") as f:
                    f.write(fixed_ca_filename) # Write the fixed name from config
                logging.info(f"Fixed CA keys backup filename ({fixed_ca_filename}) saved to {CERT_KEYS_FILENAME_STORE}")
            except Exception as write_e:
                 logging.error(f"Failed to write fixed CA keys backup filename to {CERT_KEYS_FILENAME_STORE}: {write_e}")
            return fixed_ca_filename # Return the fixed name from config
        else:
            logging.error("CA Key Pairs backup process failed or timed out during export.")
            print("\nERROR: CA Key Pairs backup process failed or timed out.")
            return None

    except Exception as e:
        logging.error(f"CA Key Pairs backup process failed with exception: {e}", exc_info=True)
        print(f"\nERROR during CA Key Pairs backup: {e}")
        if shell and shell.active:
            try:
                shell.close()
                logging.debug("Closed shell due to exception in backup_ca_key_pairs.")
            except: pass
        return None


# --- Main Execution Logic ---

def main():
    """Main function for the backup script."""
    start_time = time.time()
    logging.info("--- Starting ISE Backup Script ---")
    ssh_main = None

    try:
        # Read all configs, including the new fixed CA filename in backup_config
        ise_config, ftp_config, backup_config = read_config()

        ssh_main = ssh_connect(ise_config)
        if not ssh_main:
            sys.exit("FATAL: Could not establish main SSH connection. Exiting.")

        # Ensure repository exists or create it
        if not check_repository_exists(ssh_main, DEFAULT_REPO_NAME):
            logging.info(f"Repository '{DEFAULT_REPO_NAME}' does not exist. Creating...")
            if not create_repository(ssh_main, DEFAULT_REPO_NAME, ftp_config):
                raise RuntimeError(f"Failed to create or verify repository '{DEFAULT_REPO_NAME}'. Cannot proceed.")
            logging.info(f"Repository '{DEFAULT_REPO_NAME}' created successfully.")
        else:
            logging.info(f"Repository '{DEFAULT_REPO_NAME}' already exists.")
            print(f"Using existing repository: {DEFAULT_REPO_NAME}")

        print("\n--- Step 1: Backing Up CA Key Pairs ---")
        # Pass the backup_config dictionary containing the fixed filename
        ca_keys_backup_filename = backup_ca_key_pairs(ssh_main, DEFAULT_REPO_NAME, backup_config)
        if not ca_keys_backup_filename:
            raise RuntimeError("CA Key Pairs backup failed during export. This is critical for restore. Exiting.")
        else:
            # Filename is now the one read from config
            print(f"CA Key Pairs backup completed. Assumed filename (from config): {ca_keys_backup_filename}")


        print("\n--- Step 2: Backing Up Configuration ---")
        # Pass backup_config for config backup name and key
        config_backup_filename = initiate_backup(ssh_main, backup_config, DEFAULT_REPO_NAME)
        if not config_backup_filename:
            raise RuntimeError("Configuration backup failed. Exiting.")
        else:
             print(f"Configuration backup completed: {config_backup_filename}")


        # --- Success Summary ---
        elapsed_time = time.time() - start_time
        logging.info(f"--- ISE Backup Script Completed Successfully in {elapsed_time:.2f} seconds ---")
        print("\n======================================================")
        print(f" BACKUP PROCESS COMPLETED SUCCESSFULLY ({elapsed_time:.2f}s)")
        print("======================================================")
        # Refer to the filename read from config
        print(f"  CA Key Pairs Backup:  {ca_keys_backup_filename} (Fixed Name from config.xml)")
        print(f"  Configuration Backup: {config_backup_filename}")
        print(f"  Filenames saved to:")
        print(f"  - {CERT_KEYS_FILENAME_STORE}")
        print(f"  - {CONFIG_FILENAME_STORE}")
        print(f"  ==> Verify files ({ca_keys_backup_filename}, {config_backup_filename}) exist on FTP! <==")
        print("======================================================")

    except Exception as e:
        elapsed_time = time.time() - start_time
        logging.critical(f"Backup script failed after {elapsed_time:.2f} seconds: {e}", exc_info=True)
        print(f"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f" FATAL ERROR: Backup script failed after {elapsed_time:.2f} seconds.")
        print(f" Error: {e}")
        print(f" Check log file '{LOG_FILE}' for details.")
        print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        sys.exit(1)
    finally:
        if ssh_main:
            logging.info("Closing main SSH connection.")
            ssh_main.close()
        logging.info("--- Backup script finished ---")

if __name__ == '__main__':
    main()