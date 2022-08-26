#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: sudo $0 <network>"
    exit 1
fi

network=$1

echo ""
echo "-------- ARP Scan ----------"
echo "" 

arpResult=`nmap -PR -sn -n -T5 -oG - ${network} | awk '/Host/ {print $2}'`
# arpResult='10.56.67.200 10.56.67.77 10.56.67.156'

echo ${arpResult[*]} | tr " " "\n"

echo ""
echo "----------------------------"
echo "----------------------------"
echo ""

echo "---- TCP SYN Port Scan -----"
echo "" 

declare -A ips

for ip in ${arpResult}; do
    ports=`nmap -Pn -sS -p 1-1000 -n -T5 -oG - ${ip} | awk -F "Ports: " '/Ports/ {print $2}' | tr " " "\n" | awk -F "/" '/^[0-9]/ {print $1}'`
    
    ips[${ip}]=${ports[*]}

    if [[ -z ${ports} ]]; then
        echo "${ip} -> No open ports"
    else
        echo "${ip} -> ${ports[*]}" | tr "\n" " "
        echo ""
    fi
done

echo ""
echo "----------------------------"
echo "----------------------------"
echo ""

echo "-- nmap OS Fingerprinting --"
echo ""

declare -A nmapOSes

for ip in "${!ips[@]}"; do
    aux=`nmap -O -n -T5 ${ip} | awk '/^(OS details)|(Aggressive OS guesses)|(Too many fingerprints)/ {print}'`
    if [[ $aux == 'OS details'* ]]; then
        nmapOSes[${ip}]=`echo ${aux} | awk -F ": " '/^(OS details)|(Aggressive OS guesses)|(Too many hosts)/ {print "(normal) " $2}'`
    elif [[ $aux == 'Too many'* ]]; then
        nmapOSes[${ip}]=`echo "(error) ${aux}"`
    else
        nmapOSes[${ip}]=`echo ${aux} | awk -F ": " '/^(OS details)|(Aggressive OS guesses)|(Too many hosts)/ {print $2}' | awk -F ", " '{print "(aggressive) " $1 ", " $2 ", " $3}'`
    fi
    echo "${ip} -> ${nmapOSes[${ip}]}"
done

echo ""
echo "----------------------------"
echo "----------------------------"
echo ""

echo "--- AI OS Fingerprinting ---"
echo "" 


source /home/ruben/AIFingerprintingTool/venv/bin/activate
tool="/home/ruben/AIFingerprintingTool/venv/bin/python /home/ruben/AIFingerprintingTool/ai_fingerprinting_tool/app.py"

for ip in "${!ips[@]}"; do
    echo "${ip}:"
    ports=($(echo ${ips[${ip}]} | tr " " "\n"))

    nmapResult="${nmapOSes[${ip}]}"
    echo -e "\tnmap: ${nmapResult}"

    if [[ -z ${ports} ]]; then
        echo -e "\tAI: No open ports"
    else
        for port in "${ports[@]}"; do
            AIResult=`${tool} -p ${port} -o grep -t 5 p0f active ${ip} | awk '{print $2}'`
            
            
            if [[ ${AIResult} == "packets" ]]; then
                echo -e "\tAI (${port}): no response"
            else
                echo -e "\tAI (${port}): ${AIResult}"
            fi
        done
    fi
    echo ""
done