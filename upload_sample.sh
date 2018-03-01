#!/bin/bash

function usage(){
        echo ""
        echo "    $0 <event_id> <attachment file>"
        exit 1
}

if [ $# -ne 2 ]; then
        echo "Error: need two parameters."
        usage
fi

re_int='^[0-9]+$'
event_id="$1"
if [[ ! $event_id =~ $re_int ]]; then
        echo "Error:, event_id is not an integer."
        usage
fi

FILE="$2"
if [ ! -f "$FILE" ]; then
        echo "Error: file does not exist."
        usage
fi

FILENAME=$(basename "$FILE")

DATA=$(base64 -w0 "$FILE")

BASE_URL="https://misp.example.com/"
AUTHORIZATION_HEADER="Authorization: [auth key]"

ATTACHMENTS='{"request":{"files": [{"filename": "'$FILENAME'", "data": "'$DATA'"}]}}'

echo -e "$ATTACHMENTS"
exit

tempfile=$(mktemp)
echo -e "$ATTACHMENTS" > "$tempfile"
CURL=$(curl -s -k "${BASE_URL}events/upload_sample/$event_id" -H "$AUTHORIZATION_HEADER" -H "Accept: application/json" -H "Content-Type: application/json" --data "@$tempfile" -XPOST)
rm -f $tempfile

echo -e "$CURL"
