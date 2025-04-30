#This script is developed by KIRTI SHARMA and and it is intended to address specific security and system monitoring requirements.

#!/bin/bash
# S1 Task
# Checking if required folders exist else script will create it and then Change Directory to start the execution of script
current_date=$(date +'%Y%m%d')
mkdir -p /opt/security/errors
cd /opt/security/

if [ -d "/opt/security/working/" ]; then
    cd /opt/security/working/
else
    mkdir -p /opt/security/working/
    cd /opt/security/working/
fi

error_tgz_path="/opt/security/errors/error-$current_date.tgz"
error_log_path="/opt/security/errors/error.log"
chmod 777 "/opt/security/working"
chmod 777 "/opt/security/errors"

#Function to clean directories addesssing K11
CLEAN_DIR(){
    if [ -f "$error_tgz_path" ]; then
        rm "$error_tgz_path"
    fi 
    if [ -f "$error_log_path" ]; then
        rm "$error_log_path"
    fi 
    rm -r /opt/security/working/*
    rm -r /opt/security/errors/*
    }

# S2 Task
# Downlaod IOC file and GPG file
# Checking the given url is https formatted or not
if [[ $1 != https* ]]; then
   echo "ERROR: URL IS NOT HTTPS FORMATTED"
    CLEAN_DIR
    exit
fi

current_date=$(date +'%Y%m%d')
ioc_filename="IOC-$current_date.ioc"
gpg_filename="IOC-$current_date.gpg"
ioc_filepath="$1/$ioc_filename"
gpg_filepath="$1/$gpg_filename"

wget $ioc_filepath
wget $gpg_filepath

# S3 Task
# Validating the integrity of the IOC file
gpg --verify $gpg_filename $ioc_filename
if [ $? -eq 0 ]; then
    echo "INFO:GPG SIGNATURE VERIFICATION SUCCESSFUL"
else
    echo "ERROR:GPG SIGNATURE VERIFICATION FAILED"
    echo "FAILED S6-$(hostname) $current_date" >> "$error_log_path"
    #CLEAN_DIR
    #exit
fi

input="$ioc_filename"
# Read lines from the file into an array
mapfile -t -d $'\n' lines < "$input"

# Declare a 2D array
declare -A matrix

# Loop through each line, split on spaces, and store in the 2D array
for ((i=0; i<${#lines[@]}; i++)); do
    read -a elements <<< "${lines[i]}"
    for ((j=0; j<${#elements[@]}; j++)); do
        matrix[$i,$j]=${elements[j]}
    done
done

# Function used to validating the filehash S8
VALIDATE_FILEHASH(){
    local directory=$1
    local original_hash=$2
    local ret=$3
    local result
    if [ -d "$directory" ]; then
        #result=$(find "$directory" -type f -exec sha256sum {} \;)  #command with sha256sum commented
        result=$(find "$directory" -type f -exec /opt/security/bin/validate {} \;)  #/opt/security/bin/validate used instead of sha256sum (FAQ2)
        first_64="${result:0:64}"
        if [ "$first_64" == "$original_hash" ]; then
            if [ $ret == "true" ]; then
                echo "INFO: HASH MATCHED FOR VALIDATE/STRCHECK"
            else
                echo "WARN: IOCHASHVALUE $directory"
            fi
        else
            if [ $ret == "true" ]; then
                echo "ERROR: HASH NOT MATCHED FOR VALIDATE/STRCHECK"
                echo "S5/S8-$(hostname) $current_date" >> "$error_log_path"
                CLEAN_DIR
                exit
            else
                echo "ERROR: HASH NOT MATCHED FOR GIVEN FOLDER/FILE $directory"
                echo "S5/S8-$(hostname) $current_date" >> "$error_log_path"
            fi
        fi
        
    else
        echo "ERROR: FOLDER/FILE NOT FOUND FOR VALIDATION: $1"
        echo "S5/S8-$(hostname) $current_date" >> "$error_log_path"
    fi
}

# Function used to match the string in respective directories
STRING_MATCH(){
    local result_array=()

    if [ -d "$2" ]; then
        #result=($(grep -ilr "$1" "$2")) #command with grep commented
        result=($(/opt/security/bin/strcheck -ilr "$1" "$2")) #strcheck used instead of grep (FAQ2)
        if [ ${#result[@]} -gt 0 ]; then
            result_array=("${result[@]}")
            # Print the array elements
            for file in "${result_array[@]}"; do
                echo "WARN: STRVALUE $file"
            done
        fi
    else
        echo "WARN: FOLDER/FILE NOT FOUND FOR STRING MATCHING: $1"
        echo "WARN: FOLDER/FILE NOT FOUND FOR STRING MATCHING: $1" >> "$error_log_path"
    fi
       
}

# Function which describes invalid lines in given ioc file
INVALID_WARNING(){
    echo "WARN: INVALID LINE DETECTED IN IOC FILE at $(($1+1))"
    echo "WARN: INVALID LINE DETECTED IN IOC FILE at $(($1+1))" >> "$error_log_path"
}


# S4, S5, S8 Tasks
# Print the 2D array
for ((i=0; i<${#lines[@]}; i++)); do
    command=""
    if [ "${matrix[$i,0]:0:1}" ==  "#" ]; then
        continue
    fi
    if [ $i == 1 ]; then
        if [ "$current_date" != "${matrix[$i,0]}" ]; then
            echo "ERROR: DATESTAMP MISMATCHED"
            echo "S6-$(hostname) $current_date" >> "$error_log_path"
            CLEAN_DIR
            exit
        else
            continue
        fi
    fi
    if { [ "${matrix[$i,0]}" == "IOC" ] || [ "${matrix[$i,0]}" == "STR" ] || [ "${matrix[$i,0]}" == "VALIDATE" ] || [ "${matrix[$i,0]}" == "STRCHECK" ] ; }; then 
        for ((j=0; j<${#elements[@]}; j++)); do
            if [ "${matrix[$i,$j]}" != "" ]; then
                if [ "${matrix[$i,0]}" == "IOC" ];then
                    if [ "$j" == 0 ];then
                        command="VALIDATE_FILEHASH ${matrix[$i,2]} ${matrix[$i,1]} false"
                    elif [ "$j" -gt 2 ]; then
                        command="INVALID_WARNING $i"
                    fi
                elif [ "${matrix[$i,0]}" == "STR" ];then
                    if [ "$j" == 1 ];then
                        command="STRING_MATCH ${matrix[$i,1]} ${matrix[$i,2]}"
                    elif [ "$j" -gt 2 ]; then
                        command="INVALID_WARNING $i"
                    fi
                elif [ "${matrix[$i,0]}" == "VALIDATE" ];then
                    if [ "$j" == 1 ];then
                        command="VALIDATE_FILEHASH /opt/security/bin/validate ${matrix[$i,1]} true"
                    elif [ "$j" -gt 1 ]; then
                        command="INVALID_WARNING $i"
                        CLEAN_DIR
                        exit
                    fi
                elif [ "${matrix[$i,0]}" == "STRCHECK" ];then
                    if [ "$j" == 1 ];then
                        command="VALIDATE_FILEHASH /opt/security/bin/strcheck ${matrix[$i,1]} true"
                    elif [ "$j" -gt 1 ]; then
                        command="INVALID_WARNING $i"
                        CLEAN_DIR
                        exit
                    fi
                fi
                echo "$i $check $j ${matrix[$i,$j]} ---------------------"
            fi
        done
    else
        command="INVALID_WARNING $i"
    fi
    $command    
    check=-1
done

# S9 Task
output_file="listeningports"

# Use ss command to get listening ports and save to the file
ss -tuln > "$output_file"
echo "Listening ports have been saved to $output_file" 

# Task for Firewall rules 
output_file="firewall"
echo "Current firewall rules" > "$output_file"

# Save the current iptables rules (stdout and stderr) to the output file
iptables-save &> "$output_file"
echo "Firewall rules saved to $output_file"

# Validating files installed 
pkgdirectories=("/sbin" "/bin" "/usr/sbin" "/usr/lib" "/usr/bin")
directories=("/usr/bin")
for directory in "${pkgdirectories[@]}"; do
    if [ -d "$directory" ]; then
        # Use find with -type f and -perm to find executable files
        packages=$(ls -Lrt "$directory")

        # Check if executable_files is empty
        if [ -z "$packages" ]; then
            echo "INFO: NO PACKAGES IN $directory"
        else
            echo "INFO: CHECKING HASH VALUES FOR PACKAGES IN $directory."
            # Use a for loop to iterate over newline-separated file paths
            while IFS= read -r file; do
                pkgname="$directory/$file"
                pkgname="${pkgname:1}"
                # echo $pkgname
                #expected_hash=$(grep -i \'"$pkgname"\'$  /var/lib/dpkg/info/*.md5sums) #command with grep commented
                expected_hash=$(/opt/security/bin/strcheck -i \'"$pkgname"\'$  /var/lib/dpkg/info/*.md5sums) #strcheck used instead of grep (FAQ2)
                expected_hash="${expected_hash##*:}"
                expected_hash="${expected_hash:0:32}"
                # echo "$expected_hash"
                if [ "$expected_hash" != "" ]; then
                    current_hash=$(md5sum "$directory/$file")
                    current_hash="${expected_hash:0:32}"
                    if [ "$expected_hash" != "$current_hash" ]; then
                        echo "WARN: HASH DO NOT MATCH FOR $pkgname">>binfailure
                    fi
                fi
            done <<< "$packages"
        fi
    else
        echo "WARNING: THIS DIRECTORY DOES NOT EXIST: $directory"
    fi
done

# Reporting files created in last 48 hours
# Specify the directory to search
directory="/var/www/"

# Check if the directory exists
if [ -d "$directory" ]; then
    # Use find to locate files created in the last 48 hours
    echo "FILES THAT HAVE BEEN MODIFIED IN LAST 48 HOURS"
    find "$directory" -type f -ctime -2

    echo "SUID FILES:"
    find "$directory" -type f -perm /4000

    # List SGID files
    echo "SGID FILES:"
    find "$directory" -type f -perm /2000
else
    echo "Directory does not exist: $directory"
fi

# Verifying the executable files and converting them into non executable (part of S9)
#!/bin/bash

directories=("/var/www/images" "/var/www/uploads" )
report_file="mounting_configuration_report"

for directory in "${directories[@]}"; do
    # Check if the directory exists
    if [ -d "$directory" ]; then
        # Use find with -type f and -perm to find executable files
        executable_files=$(find "$directory" -type f -perm /u=x,g=x,o=x)

        # Check if executable_files is empty
        if [ -z "$executable_files" ]; then
            echo "INFO: NO EXECUTABLE FILES IN $directory"
        else
            echo "WARN: EXECUTABLE FILES FOUND IN $directory. LISTING THE CURRENT CONFIGURATION AND CORRECTING PERMISSIONS FOR THOSE FILES"

            # Use a for loop to iterate over newline-separated file paths
            while IFS= read -r file; do
                actual_permissions=$(stat -c %a "$file")
                chmod -x "$file"
                corrected_permissions=$(stat -c %a "$file")

                echo "INFO: $file: PERMISSIONS CHANGED $actual_permissions (FROM) ----> $corrected_permissions (TO)"
            done <<< "$executable_files"
        fi
    else
        echo "WARNING: DIRECTORY DOES NOT EXIST: $directory"
    fi
done


# Capture system configuration for mounted file systems
mount > "$report_file"
echo "System configuration report saved to $report_file"

# S10 Task
# Merge the files into single files
tar -cvzf $error_tgz_path $error_log_path
cat "$error_tgz_path" listeningports firewall mounting_configuration_report > iocreport-$current_date.txt

# Archiving the files
my_hostname=$(hostname)
tar_filename="$my_hostname-tth-$current_date.tgz"
tar -cvzf "$tar_filename" "$error_tgz_path" listeningports firewall mounting_configuration_report iocreport-$current_date.txt

# S11 Task
my_username=$(whoami)
current_year=$(date +'%Y')
current_month=$(date +'%m')

#signing the tgz file
gpg --sign-with tht2023@tht.noroff.no --detach-sig --output $tar_filename.sig $tar_filename
#Uploading tgz and sig files to remote server
rsync --ignore-errors -avz --rsync-path="mkdir -p /submission/$my_hostname/$current_year/$current_month/ && rsync" -e "ssh -i /opt/security/$3.id" "$tar_filename"* $3@$2:/submission/$my_hostname/$current_year/$current_month/     

#S12 Task
# Validating the backup
ssh -i /opt/security/"$3".id $3@$2 "cd /submission/$my_hostname/$current_year/$current_month/ && gpg --verify $tar_filename.sig $tar_filename"
if [ $? -eq 0 ]; then
    echo "INFO: GPG SIGNATURE VERIFICATION OF BACKUP SUCCESSFUL"
else
    echo "ERROR: GPG SIGNATURE VERIFICATION OF BACKUP FAILED"
fi

#S13 Task
file_size=$(du -h "$tar_filename")
#file_hash=$(find "$tar_filename" -type f -exec sha256sum {} \;)  #command with sha256sum commented
file_hash=$(find "$tar_filename" -type f -exec /opt/security/bin/validate {} \;) #validate used instead of sha256sum (FAQ2)

formatted_date=$(date +'%Y%m%d-%H:%M')

echo "INFO: NAME OF THE FILE: $tar_filename"
echo "INFO: SIZE OF THE FILE: $file_size" | cut -f1
echo "INFO: SHA256HASH VALUE OF THE FILE: $file_hash"
echo "INFO: IOC CHECK FOR $my_hostname $formatted_date OK"
CLEAN_DIR

#This script is developed by KAMAL KIRTI SHARMA.