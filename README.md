# ThreatHuntingScript

Requirement is to develop a script using the bash shell, on an Ubuntu 22.04 server system, The script is to be used to aid the SOC Threat hunting team in checking for emerging threats, and gathering information for further processing. An organisation's internal Threat Hunting Team (THT) publishes a daily list of Indicators of Comprom­ ise (loC) on their internal system. Script can be used to search for these loC's along with undertaking other related security checks on the organisations Ubuntu Servers. These are required to run with no interaction or human input.

The purpose of script is to execute checks using a given IOC file, along with generating some logs and a report. The outputs of the script are to be uploaded to a central server on completion. The script will be run via crontab between 2 and 3am every day. Output should be kept to a minimum, and limited to statements of pass/fail for each of the checks, as this output will be sent via email, and should be easy to parse for a receiving SOC system. An example direct calling of the script from the command prompt would be:
./thrhuntscr.sh https://int.iocserver/thr logs.tth.loc.org uploader123

Operating Requirements
=====================
You should take note of the following as they relate to the environment

K1 Scripts, specific tools and logs relating to this script all reside and operate in /opt/security.
This is a read-only file-system for most of the time to minimise any risk of these being changed.

K2 The server url path can change. This must not be hard coded in the script but should be taken from the first command line parameter. This is always an HTTPS url, and the protocol must be checked to be as such.

K3 The server makes use of certificate issued by a public CA

K4 The loC file is named based on the day it is created using the format IOC-yyyymmdd. ioc K5 The files are digitally signed by the Threat Hunting Team using GPG as: roc-yyyymmdd.gpg K6 The public keys needed for validating these signatures are already loaded on the servers.

K7 The loC file and accompanying signature are contained in the directory pointed to by the url in K2. KB The remote server for uploading the report is defined as the second command line parameter.

K9 The user identity to be used for access to the upload server is defined as the third command line parameter.

K10 The servers only have SSH as a login mechanism.

K11 The environment should be restored one the completion of the script. i.e. the script must return the system to the condition it was in before execution.

Functional Requirements
========================
In its operation, your script must undertake the following. Use these as a checklist to build up the func­ tionality of your script. For headings for the section they should be descriptive, but start with the relevant S value below.
S1 Use the working directory of /opt/security/working. Any downloads and/or temporary files must be placed here.

S2 Download the daily loC file from the URL specified on the command line (first parameter)

S3 Validate the integrity of the loC file. If it fails see S6.

S4 Validate that the date-stamp in the file is correct. The datestamp should match the date of the down­ load, and the filename. If it fails see S6.

S5 Use the hashes provided to confirm that the validate and strcheck tools are correct. If either fails see S6. 

S6 (FAILURE OPTION) If either the above items fail the script must generate an appropriate error mes­ sage to STDOUT stating what has failed, and exit at this point Ensure that point K11 is addressed.

S7 For the remainder, the script should handle errors as gracefully as possible, report and log them and continue. The working directory should be preserved as the file:
/opt/security/errors/error-yyyymmdd.tgz and then included in the upload if present.

S8 Details of the loC file are given on 7. The script should process this as follows:
•	For each loC listed check if it appears in the specified directory. This should must the validate command as defined above.
•	For each string listed check if it occurs in files in the specified directory. This must use the strcheck command from above.
•	Any matches for the above tasks should be written to a temporary log file in the working directory.
•	Any matches should also produce the following line to STDOUT, replacing filename with the appropriate value:
WARN: I0CHASHVALUE filenameorWARN: STRVALUE filename
•	You should undertake these checks in the most efficient way as possible.

S9 The script then needs to collect, and check some information about the local system and append this to its report along with appropriate headings:
•	Currently listening ports (with no DNS/port name resolution) and log as file listeningports .
•	Current firewall rules (with no DNS/port name resolution) and log as firewall .
•		Validate that all files installed in /sbin, /bin, /usr/sbin, /usr/bin and /usr/lib match the valid hashes in the system package database. Any that do not match should be logged to the file binfailureand included in the report under an appropriate heading.
•	Report files in /var/www/ (and sub directories) that have been created in the last 48 hours, and list any SUID/GID files in the same path regardless of modification time.
•	Ensure that both file systems mounted on /var/www/imagesand /var/www/uploadsare set as non executable (i.e. scripts cannot be run from them). If not, this should be corrected and a warning issues to STDOUT and the report, along with a copy of the system configuration for mounting file systems.

S10 On completion of the above, the script must merge the gathered files together into the report as appropriate. This should be named iocreport-yyyymmdd.txt. The generated files must be included with the text report into an appropriate archive file called hostname-tth-yyyymmdd.tgz. There must be a detached gpg signature generated before copying both to a remote system. The following are important:
•	The gpg keyid to use is: 	_
•	hostname is the name of the host the script is executing on.
•	In all cases yyyymmdd is derived from the date of execution using the YEAR, MONTH and DAY. Values must be zero-padded as required.

S11	The copy process to the central server needs to satisfy the following:
•	The copy to the central server is to be done using rsync over ssh.
•	The user identity passed on the command line must be used. The corresponding ssh identity (key) can be found in /opt/security/useridentity.id.
useridentity will be replaced with what is passed to the script in the third parameter
•	The name of the upload server is taken from the relevant command line parameter passed to the script.
•	Files must be copied to the directory /submission/hostname/YYYY /MM /on the remote system using the same hostname above. The detached signature should be put in the same place. YYYY and MM are respectively the YEAR and MONTH (1-12) of the date on which the script is executed. Value less than 10 should be zero padded.

S12	After copying is complete, you need to execute appropriate commands on the remote server to validate the backup.
•	This validation is to be based on a pgp signature of the backup.
•	You may assume all keys are loaded on the appropriate systems.

S13	Once successfully complete, the script must report the name, size of the upload (in MB) and sha256hash, along with a final line output stating:
TTH IoC Check for  hostname YYYYMMDD-HH:mm OK
Ensure to replace hostname and the YYYYMMDD-HH:mm (timestamp) with the appropriate values at the time of execution. Value less than 10 should be zero padded.

S14	Should any process fail, you must report an error. The error message must be on a new line and starting with start with:
FAILED Sx-hostname timestamp:
Where hostname is the hostname of the system the script is running on, and a timestamp as described above. Sx is the script requirement step that contained the failure. This would allow for the output to be easily processed, categorised and acted on at the SOC.

515	The script should be appropriately automated to run daily as specified. All specified output (other than what is directed to be in the report or specific files) must be written to STDOUT, in plain text, where the standard crond system will capture it and report via email.

S16	Prior to exit the script should take appropriate measures to clean up after itself, and return the envir­ onment to a clean state.
In addition to the script, you must include brief instructions on what setup/configuration is needed to get your script working and set up on a system.
•	This includes appropriate entries relating to system configuration to ensure it runs in an automated manner at a specified time.
•	This must be provided in a pdf file. This must be accompanied by and an overview of the logic and flow of the script.

An Example IOC file format :
==========================
loC file format

The format of the loC file is is as follows (lines starting with a # are comments and should be ignored in processing):
•	Datestamp - this should match the filename
•	Hashes to validate the two special tools
•		A list of IOCs. Each line starts with IOC and is followed by a sha256 cryptographic hash and a directory.The files in this directory and all bellow should be checked against the HASH.
•		String based loC's follow.These are either strings or regular expressions that may indicate problems. They should be run against all files in the specified directory (and any sub-directories).
An example layout is below.sha256hash and directory would be replaced by appropriate values.
# Datestamp this should match the filename DATE
# The hash value here should be used to check the integrity of the validation tools
# /opt/security/bin/validate and /opt/security/bin/strcheck VALIDATE sha256hash
STRCHECK sha256hash
# I0C values to check I0C sha256hash directory
# Strings follow. These are strings that may indicate problems STR string directory
An example loC file is shown below:
# Datestamp this should match the filename 20231012
# The hash value here should be used to check the integrity of the validation tools
# /opt/security/bin/validate and /opt/security/bin/strcheck
VALIDATE 5730f0e6112870ca638a21167e670502ef7fd0fffc2d438c0420e5ac63ac4c6e STRCHECK 73abb4280520053564fd4917286909ba3b054598b32c9cdfaf1d733e0202cc96
# I0C values to check
I0C de9f83707e8eb38b2028d6f4330f6b5c19a3afac49bb63c7eb8a6ff5e565487a /
I0C ac2bec8f1f09a99571924f6f4ff3075348bc8edfa4859d77292ea37d5edf8014 /var/www/uploads I0C 888e275738cf32583ee1e9bd3c40d753a46352d2e7bd37779cbf578f942be0fb	/var/www
# Strings follow. These are strings that may indicate problems STR string directory
STR IFZvbHVtZSBpbiBkcml2ZS /var/www STR PSEXECscv /data/share/windows STR "/eval\( Irot13\(/" /var/www
STR "/r0ninlm0rtixlupl0adlr57shelllphpshelllvoid\.ru/" /var/www



