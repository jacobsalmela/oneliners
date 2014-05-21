#!/bin/bash
#----------AUTHOR------------
# Jacob Salmela
# 12 March 2013
# https://github.com/jakesalmela/

#---------DESCRIPTION--------
	# A collection of powerful and useful one-liner commands for OS X

#----------------------------
###############################
########### FOR FUN ###########

# Watch star wars from the command line
telnet towel.blinkenlights.nl

# Correctly pronounce OS X.  this command is case sensitive and can be used to prove that OS X is OS Ten, not OS x
say OS X

# Rickroll the Terminal (run these types of commands with caution as any script could be executed)
curl -L http://bit.ly/10hA8iC | bash

# Send your Terminal to the Matrix
# http://osxdaily.com/2013/08/15/turn-the-terminal-into-a-matrix-style-scrolling-screen-of-binary-or-gibberish/
LC_ALL=C tr -c "[:digit:]" " " < /dev/urandom | dd cbs=$COLUMNS conv=unblock | GREP_COLOR="1;32" grep --color "[^ ]"

# Continually scroll anything
# http://osxdaily.com/2013/08/15/turn-the-terminal-into-a-matrix-style-scrolling-screen-of-binary-or-gibberish/
while (true) do echo -n "9A85Y1BF978124871248172487124871248712487124"; done

###############################
########### FINDER ############

# Remove individual app from Launchpad
sqlite3 ~/Library/Application\ Support/Dock/*.db "DELETE from apps WHERE title='APPNAME';" && killall Dock

# Remove all apps from Launchpad 
sqlite3 ~/Library/Application\ Support/Dock/*.db "DELETE from apps; DELETE from groups WHERE title<>''; DELETE from items WHERE rowid>2;"; killall Dock

# Eject all network shares
find /Volumes -maxdepth 1 -not -user root -print0 | xargs -0 umount

# Eject all external storage
find /Volumes -maxdepth 1 -not -user root -print0 | xargs -0 diskutil eject

# Expand a .pkg into a folder to explore the files--folder mount point should not exist prior to command
pkgutil --expand installer.pkg /path/to/new/folder/mountpoint

# Eject CD/DVD
drutil open tray
# or
drutil eject

# Remove .DS_Store files that sometimes cause incongruent Finder view settings
sudo find / -name ".DS_Store" -depth -exec rm {} \;

###############################
######### SYSTEM ##############

# Print the date the computer last rebooted
last | awk '/reboot/ {print substr ($0, index($0, $3))}' | head -1 

# Print the date the computer last shutdown
last | awk '/shutdown/ {print substr ($0, index($0, $3))}' | head -1 

# List the 15 most-used commands
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head -15

# Test hard disk speed by creating and removing a 500MB file
time (dd if=/dev/zero of=zerofile bs=1000 count=500;sync);rm zerofile
 
# Run 10 tests on command or script to check its performance
for i in {1..10}; do time curl http://localhost:8000 >/dev/null; done 2>&1 | grep real

# Print unicode characters in Terminal (you need to know the hex value, which can be found by right-clicking the character info, copying, and then pasting into a text editor.
# To print a sun with hex code e2 98 89
echo -e "\xe2\x98\x89"

# Get computer information CPU, hardware, etc.
sysctl -n machdep.cpu.brand_string

# Set the computer name, hostname, local hostname, or NetBIOS name
sudo scutil --set ComputerName "Macbook"
sudo scutil --set HostName "Macbook"
sudo scutil --set LocalHostName "Macbook"
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server NetBIOSName -string "Macbook"

# Erase freespace on a disk
# Change the number value to 1, 2, or 3 for number of passes (1, 7, or 35)
# 35 pass is no longer available in the GUI after 10.6, so this is nice to know
diskutil secureErase freespace 2 /dev/disk0s2

# Change boot mode
  # Boot into verbost mode
  sudo nvram boot-args="-v"
  
	# Boot into Safe Mode
  sudo nvram boot-args="-x"
  
	# Boot into Single-User Mode
  sudo nvram boot-args="-s"
  
	# Boot into Verbose mode 
  sudo nvram boot-args="-v"
  
	# Reset the boot options to normal
  sudo nvram -d boot-args

	# View current nvram settings in xml-format
  nvram -xp

# Remove KEXTs
sudo srm -rf /System/Library/Extensions/<extension.kext>
sudo touch /System/Library/Extensions

# View how many processes are allowed
getconf _CHILD_MAX
ulimit -u

# Count your processes
ps -x | wc -l

# Count another users processes
ps -xu root | wc -l

# Count all processes
ps -xa | wc -l

# Add user to admin group
sudo dseditgroup -o edit -a <username> -t user admin

# Reveal Firmware password -- older version only
python -c "print ''.join(chr(int(c, 16) ^ 170) for c in '`sudo nvram security-password`'.split('%')[1:])"

# Print RAM size
sysctl -n hw.memsize | awk '{print $0/1073741824" GB RAM"}';

# Show SMC version
ioreg -c AppleSMC | grep smc-version | cut -d'"' -f4
# or
system_profiler SPHardwareDataType | grep "SMC" | awk '{print $4}'

# Show BootROM (EFI version)
system_profiler SPHardwareDataType | grep "Boot ROM" | awk '{print $4}'

# Show Bluetooth MAC address
ioreg -c IOBluetoothHCIController | grep BluetoothDeviceAddress | grep -v BluetoothDeviceAddressData | cut -d'"' -f4

# Append all commands entered into the system log
# http://jablonskis.org/2011/howto-log-bash-history-to-syslog/
# Add this to .bash_profile 
# Used with my Single-user mode IDS
# https://github.com/jakesalmela/single-user-mode-ids
declare -rx PROMPT_COMMAND='history -a >(tee -a ~/.bash_history | logger -t "**SUM-IDS")'

# List launchd processes
# A is active
# I is inactive
# D is on demand
launchctl bslist

# Heirarchical list of launchd processes
launchctl bstree

# Speed up shutdown time by reducing timeout values
sudo defaults write /System/Library/LaunchDaemons/com.apple.coreservices.appleevents ExitTimeOut -int 5
sudo defaults write /System/Library/LaunchDaemons/com.apple.securityd ExitTimeOut -int 5
sudo defaults write /System/Library/LaunchDaemons/com.apple.mDNSResponder ExitTimeOut -int 5
sudo defaults write /System/Library/LaunchDaemons/com.apple.diskarbitrationd ExitTimeOut -int 5
sudo defaults write /System/Library/LaunchAgents/com.apple.coreservices.appleid.authentication ExitTimeOut -int 5

# Reset LaunchServices (removes duplicates/problems in Open With...)
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -kill -r -domain local -domain system -domain user

# Set a default program for a fileytpe.  Below is just one example
defaults write com.apple.LaunchServices LSHandlers -array-add '{LSHandlerContentType = "com.adobe.pdf"; LSHandlerRoleAll = "com.apple.preview";}'

###############################
###### NETWORK/INTERNET #######

# Create symbolic link to airport utility
sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/sbin/airport

# Scan available networks using the shortcut created above
airport -s

# Show all open network connections and the apps that are using them
lsof -i | grep ESTABLISHED

# Show password for Website saved in the OS X Keychain
security find-internet-password -s <url> -w

# Show all files downloaded on the Mac 
# Any file that passed through Quarantine Manager will show up here
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* 'select LSQuarantineDataURLString from LSQuarantineEvent'

# Delete list of downloaded files on the Mac
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* 'delete from LSQuarantineEvent'

# View what wireless network you are currently connected to
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/[^B]SSID/ {print $2}'

# Tell your Mac to ask for 10,000 requests to run concurrently by 50 pretend users' concurrent connection
ab -n 10000 -c 50 http://test.server.com

# Display 10 second average up/down for en0--change en0 to desired network interface
sar -n DEV 1 10 | grep -i 'average.*en0'| awk '{printf "Up:\t%.2f Kbps\nDown:\t%.2f Kbps\n", $6 / 1024, $4 / 1024 }'

# One page Web server using netcat
while true; do nc -l 80 < error.html; done

# Enable advanced network commands
ENABLE_EXPERIMENTAL_SCUTIL_COMMANDS=1 scutil --net

###############################
########### MISC ##############

# Two ways to check the md5 hash of a file
md5 file1.dmg
openssl md5 file2.dmg

# Two ways to check sha1 hash of a file
shasum file1.dmg
openssl sha1 file2.dmg

# Compare the differences between two files in the GUI (Xcode required)
opendiff file1 file2

# Convert a text document into a spoken track
say -o audio.aiff -f file.txt

# List all apps downloaded from the Mac App Store
find /Applications -path '*Contents/_MASReceipt/receipt' -maxdepth 4 -print |\sed 's#.app/Contents/_MASReceipt/receipt#.app#g; s#/Applications/##'

# Run command if user presses Ctrl+C
trap "<command_to_run>" INT

# Send a text message
# http://osxdaily.com/2014/03/12/send-sms-text-message-from-command-line/
curl http://textbelt.com/text -d number=<ten_digit_phone_number> -d "message=<your_message_here>"

# Enable App Store Degub menu
defaults write com.apple.appstore ShowDebugMenu -bool true
# Start downloading an app.  Choose Debug > Show Download Folder
# Make a hard link to copy the installer .pkg to a new location
ln /folder/from/debug/menu.pkg /new/package/location/appstoreinstaller.pkg

# Convert a manpage to HTML
# @jescala https://jamfnation.jamfsoftware.com/featureRequest.html?id=762
gzcat /usr/share/man/man1/man.1.gz | groff -mandoc -Thtml > man-1.html	

# Find out how many hours you have been logged into your Mac
ac -p | grep `whoami` | awk '{print $2}'

# Find out the user who has been logged in the most
# https://github.com/timsutton/scripts/blob/master/getMostFrequentUser/getMostFrequentUser.sh
ac -p | sort -nrk 2 | awk 'NR == 2 {print $1}'
