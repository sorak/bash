#!/bin/bash

# Create list of detected devices on same subnet.
# Useful for displaying the content of the network in Conky.

# Configuration
OUI_FILE="/tmp/oui.txt"
OUI_URL="https://www.wireshark.org/download/automated/data/manuf"
MAX_LABEL_LEN=36

# 1. Detect Subnet
SUBNET=$(ip -o -4 route show | awk '$1 ~ /^default/ {next} $0 ~ /src '"$(hostname -I | awk '{print $1}')"'$/ {print $1; exit}')
[[ -z "$SUBNET" ]] && SUBNET="192.168.1.0/24"
PREFIX=$(echo "$SUBNET" | cut -d'.' -f1-3)

# 2. Update OUI DB
if [[ ! -f "$OUI_FILE" ]] || [[ $(find "$OUI_FILE" -mtime +7 2>/dev/null) ]]; then
    wget -qO "$OUI_FILE" "$OUI_URL" 2>/dev/null || true
fi

# 3. Ping Sweep
for i in {1..254}; do
    ping -c 1 -W 1 -b "${PREFIX}.$i" &>/dev/null &
done
wait

# --- DEVICE TYPE MAPPING ---
declare -A DEVICE_TYPES=(
    "*apple*"="Apple" "*iphone*"="Apple" "*ipad*"="Apple" "*mac*"="Apple"
    "*google*"="Google" "*nest*"="Google" "*chromecast*"="Google" "*android*"="Google" "*pixel*"="Google" "*handset*"="Google"
    "*samsung*"="Samsung" "*galaxy*"="Samsung" "*lg*"="Samsung" "*sony*"="Samsung" "*philips*"="Samsung" "*tcl*"="Samsung"
    "*roku*"="TV"
    "*printer*"="Print" "*hp*"="Print" "*canon*"="Print" "*epson*"="Print" "*brother*"="Print" "*xerox*"="Print"
    "*camera*"="Cam" "*ring*"="Cam" "*wyze*"="Cam" "*arlo*"="Cam" "*webcam*"="Cam" "*security*"="Cam" "*surveillance*"="Cam"
    "*router*"="Router" "*cisco*"="Router" "*linksys*"="Router" "*netgear*"="Router" "*tp-link*"="Router" "*asus*"="Router" "*ubiquiti*"="Router"
    "*logitech*"="Audio" "*keyboard*"="Audio" "*mouse*"="Audio" "*speaker*"="Audio" "*bluetooth*"="Audio" "*bose*"="Audio" "*sonos*"="Audio" "*headphone*"="Audio" "*mobile*"="Audio" "*cellular*"="Audio" "*amplifier*"="Audio"
    "*leedarson*"="IoT" "*gaosheng*"="IoT" "*gaosh*"="IoT" "*hui*"="IoT" "*zhoush*"="IoT" "*zhousheng*"="IoT" "*espressif*"="IoT" "*mediatek*"="IoT" "*realtek*"="IoT" "*qualcomm*"="IoT" "*intel*"="IoT"
    "*smart*"="IoT" "*iot*"="IoT" "*belkin*"="IoT" "*hue*"="IoT" "*light*"="IoT" "*lamp*"="IoT" "*led*"="IoT" "*switch*"="IoT"
    "*display*"="Display" "*monitor*"="Display" "*screen*"="Display" "*panel*"="Display"
    "*phone*"="Phone"
    "*laptop*"="PC" "*notebook*"="PC" "*pc*"="PC" "*desktop*"="PC" "*workstation*"="PC"
    "*server*"="NAS" "*nas*"="NAS" "*storage*"="NAS" "*synology*"="NAS" "*qnap*"="NAS"
)

# Function to find device type from vendor name
get_device_type() {
    local vendor="$1"
    local lower_vendor=$(echo "$vendor" | tr '[:upper:]' '[:lower:]')
    
    for pattern in "${!DEVICE_TYPES[@]}"; do
        clean_pattern="${pattern//\*/}"
        if [[ "$lower_vendor" == *"$clean_pattern"* ]]; then
            echo "${DEVICE_TYPES[$pattern]}"
            return
        fi
    done
    echo ""
}

# --- Main Processing ---
# 1. Generate "Label<TAB>Octet" lines
# 2. Sort by Label, then Octet
# 3. Group by Label using awk
# 4. Output "FirstOctet<TAB>FullLine"
# 5. Sort by FirstOctet (numerically)
# 6. Remove the temporary sort key

arp -n | awk -v prefix="$PREFIX" '
/ether/ && $1 ~ "^"prefix && $3 != "(incomplete)" {
    print $1 "\t" $3
}' | sort -u | while IFS=$'\t' read -r ip mac; do
    
    last_octet="${ip##*.}"
    
    raw_mac=$(echo "$mac" | tr -d ':-' | tr '[:lower:]' '[:upper:]')
    oui_formatted="${raw_mac:0:2}:${raw_mac:2:2}:${raw_mac:4:2}"
    
    raw_host=$(dig -x "$ip" +short 2>/dev/null | head -1 | sed 's/\.$//')
    [[ -z "$raw_host" ]] && raw_host=$(host "$ip" 2>/dev/null | awk -F' ' '{print $NF}' | sed 's/\.$//' | head -1)
    
    clean_host=""
    if [[ -n "$raw_host" ]]; then
        clean_host=$(echo "$raw_host" | sed 's/\.\(attlocal\|local\|lan\|home\|corp\)\(\.[a-z]*\)*$//')
        [[ "$clean_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && clean_host=""
    fi

    is_generic=false
    if [[ -n "$clean_host" ]]; then
        case "$clean_host" in
            wlan*|eth*|ppp*|*0*|*1*|*2*|*3*|*4*|*5*|*6*|*7*|*8*|*9*) is_generic=true ;;
            ESP_*|ESP*|fuchsia-*|rtthread|unknown|device*) is_generic=true ;;
        esac
        [[ ${#clean_host} -lt 4 || "$clean_host" == "device" || "$clean_host" == "host" ]] && is_generic=true
    fi

    if [[ "$is_generic" == true ]] || [[ -z "$clean_host" ]]; then
        if [[ -n "$oui_formatted" ]]; then
            vendor_line=$(grep -m 1 "^${oui_formatted}[[:space:]]" "$OUI_FILE" 2>/dev/null)
            if [[ -n "$vendor_line" ]]; then
                vendor=$(echo "$vendor_line" | cut -f2 | awk '{print $1}')
                vendor=$(echo "$vendor" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-$MAX_LABEL_LEN)
                device_type=$(get_device_type "$vendor")
                if [[ -n "$device_type" ]]; then
                    clean_host="${vendor} (${device_type})"
                else
                    clean_host="$vendor"
                fi
            else
                clean_host="Unknown (${oui_formatted})"
            fi
        else
            clean_host="Unknown"
        fi
    else
        clean_host=$(echo "$clean_host" | cut -c1-$MAX_LABEL_LEN)
    fi

    echo -e "${clean_host}\t${last_octet}"
done | sort -t$'\t' -k1,1 -k2,2n | awk -F'\t' '
{
    label = $1
    octet = $2
    if (label == prev_label) {
        octets = octets " " octet
    } else {
        if (prev_label != "") {
            split(octets, arr, " ")
            first_octet = arr[1]
            # Output: FirstOctet (for sorting) + Tab + Full Line
            print first_octet "\t" octets " ${alignr} " prev_label
        }
        prev_label = label
        octets = octet
    }
}
END {
    if (prev_label != "") {
        split(octets, arr, " ")
        first_octet = arr[1]
        print first_octet "\t" octets " ${alignr} " prev_label
    }
}' | sort -n -k1,1 | cut -f2-

