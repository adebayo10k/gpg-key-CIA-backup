#!/bin/bash
#: Title		:key-generator-and-manager.sh
#: Date			:2019-11-15
#: Author		:adebayo10k
#: Version		:
#: Description	:Script provides gpg encryption services to the command-line user 
#: Description	: 
#: Description	:To generate new encryption keys and revocation certs, then to automatically
#: Description	:backup configurations, revocation certs and keys in appropriate ways.
#: Description	:Integrate with existing system of backup, synchronisation and encryption.
#: Description	:SSH into remotes to backup their keys too.
#: Options		:
##

## THIS STUFF IS HAPPENING BEFORE MAIN FUNCTION CALL:

command_fullpath="$(readlink -f $0)" 
command_basename="$(basename $command_fullpath)"
command_dirname="$(dirname $command_fullpath)"

if [ -d "${command_dirname}/shared-functions-library1" ]
then
	echo "LIB FILES FOUND OK"
	for file in "${command_dirname}/shared-functions-library"/shared-bash-*
	do
		source "$file"
	done
else
	# native exit
	echo "Program requires \"${command_dirname}/shared-functions-library\"."
	echo "Required file not found. Returning exit code 1. Exiting now..."
	exit 1
fi
exit 0

## THAT STUFF JUST HAPPENED (EXECUTED) BEFORE MAIN FUNCTION CALL!

function main(){
	##############################
	# GLOBAL VARIABLE DECLARATIONS:
	##############################
	program_title="gpg key backup"
	original_author="damola adebayo"
	program_dependencies=("jq" "gpg")

	declare -i max_expected_no_of_program_parameters=0
	declare -i min_expected_no_of_program_parameters=0
	declare -ir actual_no_of_program_parameters=$#
	all_the_parameters_string="$@"

	declare -a authorised_host_list=()
	actual_host=`hostname`

	config_file_fullpath="${HOME}/.config/config10k/gpg-key-backup-config.json" # a full path to a file

	test_line="" # global...

	declare -a file_fullpaths_to_encrypt=()

	##############################

	armor_option='--armor'

	##############################

	gpg_command='gpg'
	output_option='--output'
	file_path_placeholder='<filepath_placeholder>'

	synchronised_location_holding_dir_fullpath= # OR synchronised_location_parent_directory
	public_keyring_default_directory_fullpath=
	revocation_certificate_default_directory_fullpath="${HOME}/.gnupg/openpgp-revocs.d"

	this_host=$(hostname) #
	synchronised_dir_fullpath= # directory within synchronised_location_holding_dir_fullpath (only written to by this_host)
	declare -a synchronised_subdirs=() # set of directories within synchronised_dir_fullpath

	new_keygen_OK=
	new_key_rev_cert_OK=
	rev_cert_encrypt_OK=
	rev_certs_moved_OK=
	public_key_export_OK=

	################################	
	
	##############################
	# FUNCTION CALLS:
	##############################
	if [ ! $USER = 'root' ]
	then
		## Display a program header
		lib10k_display_program_header "$program_title" "$original_author"
		## check program dependencies and requirements
		lib10k_check_program_requirements "${program_dependencies[@]}"
	fi
	
	# check the number of parameters to this program
	lib10k_check_no_of_program_args

	# controls where this program can be run, to avoid unforseen behaviour
	lib10k_entry_test


	##############################
	# $SHLVL DEPENDENT FUNCTION CALLS:	
	##############################
	# using $SHLVL to show whether this script was called from another script, or from command line
	if [ $SHLVL -le 2 ]
	then
		# Display a descriptive and informational program header:
		lib10k_display_program_header

		# give user option to leave if here in error:
		lib10k_get_user_permission_to_proceed
	fi


	##############################
	# FUNCTIONS CALLED ONLY IF THIS PROGRAM USES A CONFIGURATION FILE:	
	##############################

	if [ -n "$config_file_fullpath" ]
	then
		:		
	fi

	#exit 0 #debug

	##############################
	# PROGRAM-SPECIFIC FUNCTION CALLS:	
	##############################

	# IMPORT CONFIGURATION INTO PROGRAM VARIABLES
	import_key_management_configuration

	create_all_synchronised_dirs

	# issue gpg commands to list keys for now... just to see what's there
	bash -c "gpg --list-key"
	bash -c "gpg --list-secret-keys"

	exit 0

	generate_and_manage_keys

	# ON RETURN OF CONTROL, CHECK FOR DESIRED POSTCONDITIONS
	echo "key_generator_and_manager exit code: $?" 

} ## end main function




##############################
####  FUNCTION DECLARATIONS  
##############################

function create_all_synchronised_dirs()
{
	# 3. WE MUST NOW ESTABLISH THAT ALL THE DIRECTORIES NEEDED FOR OUR SYSTEM OF BACKUP AND SYNCHRONISATION \
	#    +ALREADY EXIST, AND IF NOT, CREATE THEM:
	# TODO:  # mkdir -p // no error if exists (idempotent), make parents structure /a/b/c as needed MAY BE MORE EFFICIENT

	synchronised_dir_fullpath="${synchronised_location_holding_dir_fullpath}/${this_host}_gpg"
	echo && echo "synchronised_dir_fullpath variable now set to: $synchronised_dir_fullpath"

	# temporary rmdir during development, just until all directory creations confirmed working
	#rm -R "$synchronised_dir_fullpath"

	lib10k_test_dir_path_access "$synchronised_dir_fullpath"
	return_code=$?
	if [ $return_code -eq 0 ]
	then
		echo "synchronised_dir_fullpath ALREADY EXISTS AND CAN BE ENTERED OK"
	else
		echo && echo "synchronised_dir_fullpath DID NOT ALREADY EXIST, SO WILL NOW BE CREATED..."
		# create it..
		mkdir "$synchronised_dir_fullpath"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "synchronised_dir_fullpath CREATION WAS SUCCESSFUL"
		else
			msg="The mkdir of synchronised_dir_fullpath FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_UNEXPECTED_BRANCH_ENTERED" "$msg"
		fi	
	fi

	synchronised_subdirs=\
(\
"${synchronised_dir_fullpath}/${this_host}_public_keys_incoming" \
"${synchronised_dir_fullpath}/${this_host}_public_keys_outgoing" \
"${synchronised_dir_fullpath}/${this_host}_revocation_certificates" \
"${synchronised_dir_fullpath}/${this_host}_public_keyring_archive" \
)

	for subdir in ${synchronised_subdirs[@]}
	do
		lib10k_test_dir_path_access "$subdir"
		if [ $? -eq 0 ]
		then
			echo "subdir ALREADY EXISTS AND CAN BE ENTERED OK"
		else
			echo && echo "subdir DID NOT ALREADY EXIST, SO WILL NOW BE CREATED..."
			# create it..
			mkdir "$subdir"
			return_code=$?
			if [ $return_code -eq 0 ]
			then
				echo "subdir CREATION WAS SUCCESSFUL"
			else
				msg="The mkdir of subdir FAILED and returned: $return_code. Exiting now..."
				lib10k_exit_with_error "$E_UNEXPECTED_BRANCH_ENTERED" "$msg"
			fi	
		fi
	done

}
#################################
#
function import_key_management_configuration()
{
	get_config_values_for_all_dirs
	# for these dirs:
	# synchronised_location_holding_dir_fullpath
	# public_keyring_default_directory_fullpath
	# revocation_certificate_default_directory

	# NOW CHANGE THE VALUES
	#for dir in "$synchronised_location_holding_dir_fullpath" "$public_keyring_default_directory_fullpath"\
	#	"$revocation_certificate_default_directory_fullpath"
	for dir in "$synchronised_location_holding_dir_fullpath" "$public_keyring_default_directory_fullpath"
	do

		# sanitise absolute paths by trimming trailing / etc.
		# sanitise_absolute_path_value "${dir}"
		# echo "testline: $test_line"

		lib10k_make_abs_pathname "${dir}"
		echo "test_line has the value: $test_line"
		
		case $dir in
			$synchronised_location_holding_dir_fullpath)		synchronised_location_holding_dir_fullpath="$test_line"
				;;
			$public_keyring_default_directory_fullpath)	public_keyring_default_directory_fullpath="$test_line"
				;;
			'encryption_system')	echo "nil"; exit 1 # debug
				;;
			*) 		msg="Unrecognised profile property name. Exiting now..."
					lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
				;; 
		esac

	done

	# NOW DO ALL THE DIRECTORY ACCESS TESTS FOR IMPORTED PATH VALUES HERE.
	# REMEMBER THAT ORDER IMPORTANT, AS RELATIVE PATHS DEPEND ON ABSOLUTE.
	## NOTE: THE DIRECTORY DOESN'T EXIST UNTIL AFTER KEYS HAVE BEEN MADE FOR THE FIRST TIME! 
	for dir in "$synchronised_location_holding_dir_fullpath" "$public_keyring_default_directory_fullpath"
	do
		# this valid form test works for sanitised directory paths too
		lib10k_test_file_path_valid_form "$dir"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "DIRECTORY PATH IS OF VALID FORM"
		else
			msg="The valid form test FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
		fi	

		# if the above test returns ok, ...
		lib10k_test_dir_path_access "$dir"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "The full path to the DIRECTORY is: $dir"
		else
			msg="The DIRECTORY path access test FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_REQUIRED_FILE_NOT_FOUND" "$msg"
		fi
	done

	echo "synchronised_location_holding_dir_fullpath:"
	echo -e "$synchronised_location_holding_dir_fullpath"
	echo && echo
	
	echo "public_keyring_default_directory_fullpath:"
	echo -e "$public_keyring_default_directory_fullpath"
	echo && echo
	
	echo "revocation_certificate_default_directory:"
	echo -e "$revocation_certificate_default_directory"
	echo && echo

}

##############################

# returns 
function export_public_keys
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	public_key_export_OK=false
	
	echo "public_key_export_OK is set to: $public_key_export_OK"

	# ascii armour export the new public key from its' keyring to the sync'd location
	gpg --armor --output "${synchronised_dir_fullpath}/${this_host}_public_keys_outgoing/pub_key_${this_host}_$(date +'%F@%T').asc" \
	--export "$user_id"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE EXPORT OF PUBLIC KEYS WAS SUCCESSFUL"
		public_key_export_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE EXPORT OF PUBLIC KEYS FAILED"
		public_key_export_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "public_key_export_OK was set to: $public_key_export_OK"
}
#######################################
# returns 
function rename_and_move_revocation_certificates
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	rev_certs_moved_OK=false
	
	echo "rev_certs_moved_OK is set to: $rev_certs_moved_OK"

	# rename all encrypted revocation certificates to the sync'd location
	mv "$revocation_certificate_default_directory_fullpath"/* "${synchronised_dir_fullpath}/${this_host}_revocation_certificates"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTED REVOCATION CERTS. RENAME AND MOVE WAS SUCCESSFUL"
		rev_certs_moved_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTED REVOCATION CERTS. RENAME AND MOVE FAILED"
		rev_certs_moved_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "rev_certs_moved_OK was set to: $rev_certs_moved_OK"
}
#######################################
# WE KNOW THAT REVOCATION CERTS AND PRIVATE KEYS SHOULD NEVER EXIST ON THE SAME HOST, BUT WHILE REV CERTS DO \
# + EXIST ON OUR SYSTEM, WE'LL USE ENCRYPTION AND SHREDDING TO ACHEIVE CONFIDENTIALITY AND INTEGRITY
# gpg encrypt both user-generated and pre-generated revocation certs in the GnuPG default location	
function encrypt_revocation_certificates
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	rev_cert_encrypt_OK=false	
	echo "rev_cert_encrypt_OK is set to: $rev_cert_encrypt_OK"

	touch "${synchronised_dir_fullpath}/${this_host}_revocation_certificates/keypair_fingerprint_list"
	
	# we first just need to populate file_fullpaths_to_encrypt array
	# we'll also append a list of fingerprints in a synchornised location file
	# we'll use file_fullpaths_to_encrypt to create a string and pass it into file-encrypter.sh
	for file in "${revocation_certificate_default_directory_fullpath}"/*
	do
		#incoming_array+=( "${file}" )
		file_fullpaths_to_encrypt+=( "${file}" )
		if [[ $file =~ .rev$ ]]
		then
			fingerprint="${file%.rev}"; fingerprint="${fingerprint##*'/'}"
			#echo "$fingerprint"
			echo "$fingerprint" >> "${synchronised_dir_fullpath}/${this_host}_revocation_certificates/keypair_fingerprint_list"
		fi
	done

	echo && echo "file_fullpaths_to_encrypt ARRAY HAS NOW BEEN POPULATED WITH REVOCATION CERTS"

	# BASH ARRAYS ARE NOT 'FIRST CLASS VALUES' SO CAN'T BE PASSED AROUND LIKE ONE THING\
	# - so since we're only intending to make a single call\
	# to file-encrypter.sh, we need to make an IFS separated string argument
	for filename in "${file_fullpaths_to_encrypt[@]}"
	do
		#echo "888888888888888888888888888888888888888888888888888888888888888888"
		string_to_send+="${filename} " # with a trailing space character after each
	done

	# now to trim that last trailing space character:
	string_to_send=${string_to_send%[[:blank:]]}

	echo "${string_to_send}"

	# encrypt whatever we put in that file_fullpaths_to_encrypt (should normally be just 2 files\
	# - the pre and user-generated rev certs)
	
	# we want to replace EACH revocation certificate to be replaced by an encrypted version...
	# our encryption script takes care of shredding everything it encrypts!
	# TODO: THINK... WE COULD ENCRYPT WITH A DIFFERENT KEY - A KEY FOR THIS PURPOSE ONLY?
	
	echo && echo "JUST ABOUT TO CALL file-encrypter.sh ..."

	# ... so, we call file-encrypter.sh script to handle the file encryption job
	# the command argument is deliberately unquoted, so the default space character IFS DOES separate\
	# the string into arguments
	# we can use ANY available private key for this, not just the newly generated one! tell the user!
	"${command_dirname}/gpg-json-encryption-profiles/gpg-file-encrypt.sh" $string_to_send

	encrypt_result=$?
	if [ $encrypt_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$encrypt_result\" THEREFORE REVOCATION CERTIFICATE ENCRYPTION WAS SUCCESSFUL"
		rev_cert_encrypt_OK=true
	else
		echo && echo "RETURNED VALUE \"$encrypt_result\" THEREFORE REVOCATION CERTIFICATE ENCRYPTION FAILED"
		rev_cert_encrypt_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "rev_cert_encrypt_OK was set to: $rev_cert_encrypt_OK"
}
#######################################
# returns 
function generate_revocation_certificate
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	new_key_rev_cert_OK=false
	
	echo "new_key_rev_cert_OK is set to: $new_key_rev_cert_OK"

	# generate a revocation certificate (user-generated) for the new key-pair
	# for now we'll just hard code for an ascii (the default) format certificate

	gpg --output "${revocation_certificate_default_directory_fullpath}/revoke_cert_${this_host}_$(date +'%F@%T').asc" \
	--gen-revoke "$user_id"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE USER-GENERATED REVOCATION CERTIFICATE WAS SUCCESSFUL"
		new_key_rev_cert_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE USER-GENERATED REVOCATION CERTIFICATE FAILED"
		new_key_rev_cert_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "new_key_rev_cert_OK was set to: $new_key_rev_cert_OK"
}
#######################################
# nothing returned, as no other function depends on the outcome of this task. just print messages.
function backup_public_keyrings
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# public keyring backup:
	for pubkeyring in {"pubring.gpg","pubring.kbx"}
	do

		# copy old public keyring (each format) from synchronised location to archive location
		lib10k_test_file_path_access "${synchronised_dir_fullpath}/${pubkeyring}"
		if [ $? -eq 0 ]
		then
			echo && echo "AN EXISTING \"${pubkeyring}\" PUBLIC KEYRING WAS FOUND IN THE SYNC'D LOCATION"
			# rename and archive this existing public keyring
			mv "${synchronised_dir_fullpath}/${pubkeyring}" \
			"${synchronised_dir_fullpath}/${this_host}_public_keyring_archive/${pubkeyring}_before.$(date +'%F@%T')"
			echo && echo "THE EXISTING \"${pubkeyring}\" PUBLIC KEYRING WAS RENAMED AND ARCHIVED"
		else
			echo && echo "COULDN'T FIND AN EXISTING \"${pubkeyring}\" PUBLIC KEYRING IN THE SYNC'D LOCATION"		
		fi

		# copy new public keyring (each format) from default location to synchronised location
		lib10k_test_file_path_access "$public_keyring_default_directory_fullpath/${pubkeyring}"
		if [ $? -eq 0 ]
		then
			echo && echo "A NEW \"${pubkeyring}\" PUBLIC KEYRING WAS FOUND IN THE GnuPG DEFAULT LOCATION"
			# copy the new version to the sync'd location
			cp "$public_keyring_default_directory_fullpath/${pubkeyring}" \
			"${synchronised_dir_fullpath}"
			echo && echo "THE LATEST \"${pubkeyring}\" PUBLIC KEYRING HAS NOW BEEN COPIED TO THE SYNC'D LOCATION"
		else
			echo && echo "COULDN'T FIND A NEW \"${pubkeyring}\" PUBLIC KEYRING IN THE GnuPG DEFAULT LOCATION"		
		fi

	done

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}
#######################################
# set the value of the new_keygen_OK global
function generate_public_keypair
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	#test_uid=$1

	#new_keypair_user_id=
	new_keygen_OK=false 

	#echo "new_keypair_user_id is set to: $new_keypair_user_id"
	echo "new_keygen_OK is set to: $new_keygen_OK"


	gpg --full-gen-key	
	test_result=$?
	
	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTION WAS SUCCESSFUL"
		new_keygen_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTION FAILED"
		new_keygen_OK=false
	fi


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "new_keygen_OK was set to: $new_keygen_OK"
}
#######################################
# returns zero if user-id (or substring of it) already used in public keyring
function test_uid_in_pub_keyring
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_uid=$1
	
	echo "test_uid is set to: $test_uid"

	gpg --list-key | grep "$test_uid" &>/dev/null
	test_result=$?

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
#######################################
# returns zero if 
function test_email_valid_form
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_email=$1
	
	echo "test_email is set to: $test_email"

	if [[ $test_email =~ $EMAIL_REGEX ]]
	then
		echo "THE FORM OF THE INCOMING PARAMETER IS OF A VALID EMAIL ADDRESS"
		test_result=0
	else
		echo "PARAMETER WAS NOT A MATCH FOR OUR KNOWN EMAIL FORM REGEX: "$EMAIL_REGEX"" && sleep 1 && echo
		echo "Returning with a non-zero test result..."
		test_result=1
		return $E_UNEXPECTED_ARG_VALUE
	fi 

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
##############################
function set_working_user_id
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# in order for script to use a variable (user_id) when creating certificate revocation and public key export commands, \
	# we now assign an identifying email address to the global user_id variable:
	# we're doing it here just to make sure we use the same one during interactive key generation:
	
	while true
	do

		user_id=""

		echo && echo "ENTER THE UNIQUE USER-ID (email address) THAT UR ABOUT TO USE FOR KEY GEN:" && echo
		read user_id
		echo && echo "You specified the user-id: $user_id" && echo

		# test user_id for valid email form
		test_email_valid_form "$user_id"
		valid_email_result=$?
		echo " "

		if [ $valid_email_result -eq 0 ]
		then
			echo && echo "EMAIL ADDRESS \"$user_id\" IS VALID"
			#break
		else
			echo && echo "THAT'S NO VALID EMAIL ADDRESS, TRY AGAIN..."
			continue
		fi

		# ensure the user specified email user-id (or substring of it) doesn't already exist in the public keyring
		test_uid_in_pub_keyring "$user_id"
		uid_in_keyring_result=$?
		echo " "
		
		# positive result is bad
		if [ $uid_in_keyring_result -ne 0 ]
		then
			echo && echo "OK TO USE EMAIL ADDRESS \"$user_id\" "
			break
		else
			echo && echo "THAT'S A VALID EMAIL ADDRESS, BUT IT'S ALREADY BEING USED :( TRY AGAIN..."
			continue # just in case we add more code after this block
		fi

	done

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

##############################
# the act of generating a new key-pair also triggers its' automatic backup, rev. cert generation
# and encryption etc.
function generate_and_manage_keys
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo	
	
	set_working_user_id

	##############################################
	
	echo && echo "[1] EMAIL ADDRESS USER ID VALIDATION COMPLETE... MOVING ON TO:"
	echo && echo "KEY GENERATION"

	echo && echo "[1] KNOWN DEPENDENCIES: "
	echo "NONE"

	echo && echo "[1] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
	echo && echo "...WAIT ...YOU'RE ABOUT TO BE ASKED FOR SOME KEY GENERATION PARAMETERS..."	
	sleep 12; echo && echo "PRESS ENTER NOW TO CONTINUE" && echo
	
	generate_public_keypair

	##############################################

	echo && echo "[2] KEY GENERATION COMPLETE... MOVING ON TO:"
	echo && echo "KEYRING BACKUP ACTIVITIES"

	echo && echo "[2] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[2] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF KEY GENERATION... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi
	
	backup_public_keyrings

	##############################################

	echo && echo "[3] KEYRING BACKUP ACTIVITIES PRESUMED COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. GENERATION"

	echo && echo "[3] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"
	echo "2. user_id"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[3] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF KEY GENERATION... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi

	generate_revocation_certificate

	##############################################

	echo && echo "[4] USER-GENERATED REVOCATION CERT. ACTIVITIES COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. ENCRYPTION"

	echo && echo "[4] KNOWN DEPENDENCIES: "
	echo "1. REVOCATION CERT. GENERATION"

	if [ $new_key_rev_cert_OK = true ]
	then
		echo && echo "[4] EXISTENCE OF REVOCATION CERT. GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT ...YOU'RE ABOUT TO BE ASKED FOR SOME ENCRYPTION PARAMETERS..."	
		sleep 12; echo && echo "PRESS ENTER NOW TO CONTINUE" && echo
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF REVOCATION CERT. GENERATION... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi
	
	encrypt_revocation_certificates

	##############################################

	echo && echo "[5] REVOCATION CERT. ENCRYPTION (INCLUDING SHRED) NOW COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. RENAME AND MOVE"

	echo && echo "[5] KNOWN DEPENDENCIES: "
	echo "1. REVOCATION CERT. ENCRYPTION"

	if [ $rev_cert_encrypt_OK = true ]
	then
		echo && echo "[5] EXISTENCE OF REVOCATION CERT. ENCRYPTION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12; echo && echo "PRESS ENTER NOW TO CONTINUE" && echo
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF REVOCATION CERT. ENCRYPTION... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi

	rename_and_move_revocation_certificates

	##############################################

	echo && echo "[6] REVOCATION CERT. RENAME AND MOVE NOW COMPLETE... MOVING ON TO:"
	echo && echo "PUBLIC KEYS EXPORT"

	echo && echo "[6] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"
	echo "2. user_id"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[6] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12; echo && echo "PRESS ENTER NOW TO CONTINUE" && echo
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF KEY GENERATION... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi

	export_public_keys

	##############################################

	echo && echo "[7] PUBLIC KEYS EXPORT NOW COMPLETE... MOVING ON TO:"
	echo && echo "FINISHING..."

	echo && echo "[7] KNOWN DEPENDENCIES: "
	echo "1. PUBLIC KEYS EXPORT"

	if [ $public_key_export_OK = true ]
	then
		echo && echo "[7] EXISTENCE OF PUBLIC KEYS EXPORT CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12; echo && echo "PRESS ENTER NOW TO CONTINUE" && echo
	else
		# exit, as nothing further can be done
		msg="ABORTING DUE TO FAILURE OF PUBLIC KEYS EXPORT... Exiting now..."
		lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
	fi

	echo && echo "[7] WE'VE NOW COMPLETED THE WHOLE PROCESS OF KEY GENERATION AND MANAGEMENT...WAIT" && echo
	sleep 4

	##############################################


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

######################################

main "$@"; exit
