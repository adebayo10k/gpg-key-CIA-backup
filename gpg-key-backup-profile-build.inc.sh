#!/bin/bash

# this function imports the json profile data and then ...

function get_config_values_for_all_dirs () 
{
	config_file_fullpath="${HOME}/.config/gpg-key-backup-config.json" # a full path to a file

	echo "config_file_fullpath set to $config_file_fullpath"

	# NOTES ON THE jq PROGRAM:
	#==================  
	# the -r option returns unquoted, line-separated string
	# the -j option gives unquoted and no newline
	# no option gives quoted, line-separated strings

	# values that are returned by jq as 'concatenated strings to be arrayed' get an IFS.
	# single string values don't. 
	 # conveniently, the same sed command is applied to both (all) cases though!
	# therefore, for consistent handling, everything was single-quoted.

	get_and_assign_data

}

##########################################################

# store each retrieved profile as structured data in memory.
# this avoids going back to read from disk.
function get_and_assign_data()
{	

	syncd_host_dir_string=$(cat "$config_file_fullpath" | jq -r '.synchronisedHostDir') 
	echo "syncd_host_dir_string:"
	echo -e "$syncd_host_dir_string"
	echo && echo

	synchronised_location_holding_dir_fullpath="$syncd_host_dir_string"
	
	###

	pub_keyring_dir_string=$(cat "$config_file_fullpath" | jq -r '.defaultPublicKeyringDir') 
	echo "pub_keyring_dir_string:"
	echo -e "$pub_keyring_dir_string"
	echo && echo

	public_keyring_default_directory_fullpath="$pub_keyring_dir_string"

	###

	rev_cert_dir_string=$(cat "$config_file_fullpath" | jq -r '.defaultRevCertDir') 
	echo "rev_cert_dir_string:"
	echo -e "$rev_cert_dir_string"
	echo && echo

	revocation_certificate_default_directory="$rev_cert_dir_string"

}

##########################################################
