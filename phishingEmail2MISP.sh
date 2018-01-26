#!/bin/bash
# https://forums.contribs.org/index.php?topic=49765.0

hash jq 2>/dev/null || { echo >&2 "Error: This script uses the 'jq' program, it needs to be installed for this to work."; echo >&2 "You can find it here: https://github.com/stedolan/jq"; exit 1; }
hash pup 2>/dev/null || { echo >&2 "Error: This script uses the 'pup' program, it needs to be installed for this to work."; echo >&2 "You can find it here: https://github.com/EricChiang/pup/releases/"; exit 1; }

# FLag to Save the attachments and the texz on a folder named after the email subject
SAVE_ATTACHMENTS=1
FOLDER_ATTACHMENTS="./"

# Regular Expression for the "Received: by" email Header
# 1) SMTP sender server IP
# 2) SMTP standard
# 3) SMTP email id
# 4) email date
RE1='Received:\s+by\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(\s+with\s+[A-Z]+)?(\s+id\s+[0-9A-Za-z.]+)?;\s+([^() ][^()]+[^() ])\s+\([^()]+\)'

# OLD Regular Expression for the "Received: from" email Header
# 1) SMTP sender server name/IP
# 2) SMTP sender server name
# 3) SMTP sender server IP
# 4) SMTP receiver server name/IP
# 5) SMTP service software
# 6) SMTP standard
# 7) SMTP email id
# 8) SMTP email address
# 9) SMTP other
# 10) email date
#OLD_RE2='Received:\s+from\s+([^ \/$.?#].[^ ]*|\[?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]?)\s+\(([^ \/$.?#].[^ ]*)\s+\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?\)\s+by\s+([^ \/$.?#].[^ ]*)(\s+\([^)(]+\))?(\s+with\s+[a-zA-Z]+)?(\s+id\s+[0-9A-Za-z.]+)?(\s+for\s+<[^ \/$.?#].[^ ]*>)?\s+([^;]+);\s+([^()][^()]+[^()])\s+\([^()]+\)'

# Regular Expression for the "Received: from" email Header
# 1) SMTP sender server name/IP
# 2) SMTP sender server name
# 3) SMTP sender server IP
# 4) Other SMTP stuff, depends on the SMTP server
# 5) SMTP processing date
RE2='Received:\s+from\s+([^(]+)\s+\(([^0-9)[ ][^ )[]+)?\s*\[?([^])[]+)\]?\)([^;]+)?;\s+([^()][^()]+[^()])\s*(\([^()]+\))?'

# Regular Expressin for the "To", "CC" and similar email Headers
RE_EMAIL_PARSE="([^<]+)\s<([^>]+)"

# URL Regex based on https://mathiasbynens.be/demo/url-regex
RE_URL='(https?|ftp):\/\/([^[:space:]\/$.?#].[^[:space:])\\>"'"'"']*)'

WHITELIST='(www.pdf-tools.com|.google.com|.google.cl|.microsoft.com|.yahoo.com)'

function extractHeaders {
	local text="$1"
	local res=$(echo -e "$text" | grep -B10000 -m1 -e "^\s*$")

	echo -e "$res"
}

function splitAndParseEmails {
	local emails="$1"
	local attr=""

	email_list=$(echo "$emails" | tr "," "\n")
	while read -r addr
	do
		if [[ "$addr" =~ $RE_EMAIL_PARSE ]]; then
			display=${BASH_REMATCH[1]}
			attr="$attr"',{"type":"email-'$datatype'-display-name","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'$display'"}'
			email=${BASH_REMATCH[2]}
			attr="$attr"',{"type":"email-'$datatype'","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'$email'"}'
		else
			attr="$attr"',{"type":"email-'$datatype'","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'$aux'"}'
		fi
	done <<< "$email_list"

	echo "$attr"
}

function generateJSONAttr {
	local EH=$1
	local attr='{"type":"email-subject","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'$(getEmailSubject)'"}'
	local lista=("from" "sender" "to" "cc" "reply-to" "message-id" "x-mailer")

	for data in "${lista[@]}"
	do
		aux=$(echo -e "$EH" | grep -ie "^${data}:" | sed -e "s/${data}: \+//I" -e 's/\"/\\\"/g' -e 's/\r$//')

		if [[ "$data" == "from" ]];then
			datatype="src"
		elif [[ "$data" == "sender" ]];then
			datatype="src"
		elif [[ "$data" == "to" ]]; then
			datatype="dst"
		elif [[ "$data" == "cc" ]]; then
			datatype="dst"
		else
			datatype=$data
		fi

		if [ -n "$aux" ];then
			if [[ "$datatype" == "src" || "$datatype" == "dst" ]]; then
				res=$(splitAndParseEmails "$aux")
				attr="${attr}${res}"
			else
				attr="$attr"',{"type":"email-'$datatype'","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'$aux'"}'
			fi
		fi
	done

	echo -e "$attr"
}

function assignReceivedFrom {
	declare -a line=("${!1}")

	local attr=""

	for i in "${!line[@]}"; do
		if [ $i -gt 0 ] && [ -n "${line[$i]}" ] && [[ ! "${line[$i]}" =~ "unknown" ]] && [[ "127.0.0.1" != "${line[$i]}" ]] ; then
			case "$i" in
				1) 
					local aux=$(echo ${line[$i]} | sed -e "s/[][]//g" -e "s/\.$//")
					if [[ "$aux" =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
						attr="$attr"',{"type":"ip-src","category":"Network activity","to_ids":"0","distribution":"5","value":"'${aux}'"}'
					else
						attr="$attr"',{"type":"domain","category":"Network activity","to_ids":"0","distribution":"5","value":"'${aux}'"}'
					fi
				;;
				2) 
					local aux=$(echo ${line[$i]} | sed -e "s/[][]//g" -e "s/\.$//")
					attr="$attr"',{"type":"domain","category":"Network activity","to_ids":"0","distribution":"5","value":"'${aux}'"}'
				;;
				3) 
					local aux=$(echo ${line[$i]} | sed -e "s/[][]//g")
					attr="$attr"',{"type":"ip-src","category":"Network activity","to_ids":"0","distribution":"5","value":"'${aux}'"}'
				;;
				*) ;;
			esac
		fi
	done

	echo "$attr"
}

function sortReceivedFromHeader {
	local EH="$1"

	local res=$(echo -e "$EH" | grep -e "Received:")
	local ATTR=""

	printf '%s\n' "$res" | while IFS= read -r line
	do
		if [[ "$line" =~ $RE1 ]]; then
			receiver=${BASH_REMATCH[1]}
			mydate=$(date --date="${BASH_REMATCH[4]}" -u)
		elif [[ "$line" =~ $RE2 ]]; then
			sender=$(echo ${BASH_REMATCH[1]} | sed -e "s/[][]//g" )
			mydate=$(date --date="${BASH_REMATCH[5]}" -u)

			ATTR=$(assignReceivedFrom BASH_REMATCH[@])
			echo "$ATTR"
		fi
	done

}

function getEmailSubject {
	local email_subject=$(echo -e "$EH" | grep -ie "^subject:" | sed -re "s/subject:\s+(.*)$/\1/I")
	if [ -z "$email_subject" ]; then
		email_subject="(sin asunto)"
	fi

	echo $email_subject
}

function getBoundary {
        echo $(echo -e "$1" | grep -e "boundary" -m1 | sed -re 's/^.*boundary="([^"]+)".*$/\1/I')
}

function extractBody {
        local text="$1"
        local boundary="$2"
        #boundary=$(echo -e "$text" | grep -e "boundary" -m1 | sed -re 's/^.*boundary="([^"]+)".*$/\1/I')
        if [[ -n "$boundary" ]]; then
                local BODY=$(echo -e "$text" | sed -ne '/--'${boundary}'/,$p')
                echo -e "$BODY"
        else
		local BODY=$(echo -e "$text" | sed -e "0,/^\s*$/d")
		local ct=$(echo -e "$text" | grep -m1 -ie "^content-type")
                echo "$ct"
		echo ""
		echo -e "$BODY"
        fi
}

function separateByBoundary {
        local text="$1"
        local boundary="$2"
        local i=1

	local res=""
	local strings=""

        while [ -n "$text" ]
        do
		if [ -n "$boundary" ]; then
	                part=$(echo -e "$text" | sed -ne '0,/'${boundary}'/p' | grep -v -e "${boundary}")
		else
			part=$(echo -e "$text")
		fi

                head=$(echo -e "$part" | grep -B1000 -m1 -e "^\s*$" | sed -e '/^\s*$/d')
                body=$(echo -e "$part" | sed -e '1,/^\s*$/d')
                if [ -n "$head" ];then
                        local ct=$(echo -e "$head" | grep -ie "Content-Type:")
                        if [[ "$ct" =~ "Content-Type: multipart" ]];then
                                local new_boundary=$(getBoundary "$head")
				res="${res}"$(separateByBoundary "$body" "$new_boundary")
                        else
                                local filename=$(echo -e "$head" | grep "Content-Disposition" | sed -re 's/^.*filename="?([^"]+)"?$/\1/' )
                                if [[ -z "$filename" ]];then
                                        filename=$(echo -e "$ct" | sed -re 's/Content-Type:\s*([^;]+);?.*$/\1/I' -e 's/\//_/g')".raw"
                                fi

				if [ -n "$(echo -e "$head" | grep -e 'Content-Transfer-Encoding: base64')" ];then
                                	b64=$(echo -e "$body" | paste -sd "")
					text=$(echo -e "$b64" | base64 -d -)
					strings=$(checkURLOnFile "$text" 2)
				else
					if [[ "$ct" =~ "Content-Type: text/plain" ]];then
						strings=${strings}$(checkURLOnFile "$body" 0)
					elif [[ "$ct" =~ "Content-Type: text/html" ]];then
						strings=${strings}$(checkURLOnFile "$body" 1)
					else
						strings=${strings}$(checkURLOnFile "$body" 2)
					fi

                                	b64=$(echo -e "$body" | base64 -w 0 -)
				fi
				res="${res}"'{"filename": "'$filename'", "data": "'$b64'"}'

				# Now that we have it, should we save it in a folder also?
				if [ $SAVE_ATTACHMENTS -eq 1 ];then
					saveAttachment "$filename" "$b64"
				fi
                        fi
                fi

		if [ -n "$boundary" ]; then
	                text=$(echo -e "$text" | sed -e '0,/'${boundary}'/d')
		else
			text=""
		fi
        done

	if [ -n "$strings" ];then
		echo "${strings}" | sed -e "s/}{/},{/g"
	fi
	echo "${res}" | sed -e "s/}{/},{/g"
}

function saveAttachment {
	local filename="$1"
	local content64="$2"

	local dirname="[$(date +%F)] - $(getEmailSubject)/"
	local fulldir="${FOLDER_ATTACHMENTS}${dirname}"

	if [ ! -d "$fulldir" ];then
		mkdir -p "${fulldir}"
	fi

	echo -e "$content64" | base64 -d - > "${fulldir}${filename}"
}

function checkWhitelist {
        URL="$1"
        if [[ "$URL" =~ $WHITELIST ]]; then
                echo "0"
        else
                echo "1"
        fi
}

function checkURLOnFile {
	local FILE="$1"
	# 0 plaintext
	# 1 html
	# 2 binary
	local TYPE="$2"
	if [ -z $TYPE ]; then
	        TYPE=2
	fi
	
	if [ $TYPE -eq 0 ]; then
	        text=$(echo -e "$FILE")
	elif [ $TYPE -eq 1 ]; then
	        text=$(echo -e "$FILE" | pup)
	elif [ $TYPE -eq 2 ]; then
	        text=$(echo -e "$FILE" | strings)
	fi
	
	while read -r line
	do
	        if [[ "$line" =~ $RE_URL ]]; then
	                res=$( checkWhitelist "${BASH_REMATCH[0]}" )
	                if [ $res -eq 1 ]; then
				urls=$urls$(echo '{"type":"url","category":"Payload delivery","to_ids":"1","distribution":"5","value":"'${BASH_REMATCH[0]}'"}')
	                fi
	        fi
	done <<< "$text"
	echo "$urls" | sed -e "s/}{/},{/g"
}

# Fetching the file
filename="$1"
if [ $# -ne 1 ]; then
	echo "ERROR: Bad usage"
	echo "        $0 [email_file]"
	exit
elif [ ! -f "$1" ];then
	echo "ERROR: File does not exist"
	exit
fi

# Cleaning the file so we can parse it better
# Patched the sed regex using http://www.grymoire.com/Unix/Sed.html
WHOLE_FILE=$(cat "$filename" | tr -s '\t' '\040' | sed -re 's/\x0d//g' | sed -e ':t;/\n\n/ba;$ba;N;b t;:a;s/\n / /g;t t')
WHOLE_FILE="${WHOLE_FILE}\n"

# Extract the Headers
EH=$(extractHeaders "$WHOLE_FILE")

BASE_DATA='{"Event":{"date":"'$(date +%F)'","threat_level_id":"1","info":"[Phishing Email] '$(getEmailSubject)'","analysis":"0","distribution":"1"}}'
ATTR=$(generateJSONAttr "$EH")
ATTR_HEADERS=$(sortReceivedFromHeader "$EH")

# Extract the Body
boundary=$(getBoundary "$WHOLE_FILE")

#if [ -n "$boundary" ]; then
	EB=$(extractBody "$WHOLE_FILE" "$boundary")

	ATTACH=$(separateByBoundary "$EB" "$boundary")
	ATTR_URL=""
	# Workaround to get the URLs from the URL parser
	if [ $(echo -e "$ATTACH" | wc -l) -eq 2 ];then
		ATTR_URL=","$(echo -e "$ATTACH" | head -n 1)
		ATTACH=$(echo -e "${ATTACH}" | tail -n 1)
	fi

	ATTACHMENTS='{"request":{"files": ['$ATTACH'], "distribution": 5}}'
#fi

ATTR_OTHER=',{"type":"comment","category":"Other","to_ids":"0","distribution":"5","value":"Event created automatically by custom email2misp script"}'
ATTR=$(echo "[${ATTR}${ATTR_HEADERS}${ATTR_URL}${ATTR_OTHER}]" | jq -c ".|unique")

# Remove this when ready
echo "Checking the obtained data..."
echo -e "$BASE_DATA"
echo -e "$ATTR"
echo -e "$ATTACHMENTS"
exit

BASE_URL="https://example.com/"
AUTHORIZATION_HEADER="Authorization: [hay que poner algo]"

CURL=$(curl -s -k "${BASE_URL}events/" -H "$AUTHORIZATION_HEADER" -H "Accept: application/json" -H "Content-Type: application/json" --data "$BASE_DATA" -XPOST)
event_id=$(echo "$CURL" | jq -r ".Event.id")

if [[ "$event_id" != "null" ]];then
	echo "Event ID: $event_id has been creted succesfully"
	CURL=$(curl -s -k "${BASE_URL}attributes/add/$event_id" -H "$AUTHORIZATION_HEADER" -H "Accept: application/json" -H "Content-Type: application/json" --data "$ATTR" -XPOST)

	if [ -n "$ATTACHMENTS" ]; then
		# Workaround because files can be too big
		tempfile=$(mktemp)
		echo -e "$ATTACHMENTS" > "$tempfile"
		CURL=$(curl -s -k "${BASE_URL}events/upload_sample/$event_id" -H "$AUTHORIZATION_HEADER" -H "Accept: application/json" -H "Content-Type: application/json" --data "@$tempfile" -XPOST)
		rm -f $tempfile
	fi
else
	echo "Event ID: Not found"
	echo "$CURL"
fi
