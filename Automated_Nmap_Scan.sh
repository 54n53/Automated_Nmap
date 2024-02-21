#!/bin/bash

# Solicitar al usuario que ingrese la dirección IP
read -p "Ingrese la dirección IP a escanear: " ip_address

# Verificar si se ingresó una dirección IP válida
if ! [[ $ip_address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Dirección IP no válida. Por favor, ingrese una dirección IP válida."
    exit 1
fi

# Realizar ping a la dirección IP para verificar si está activa
if ping -c 4 $ip_address &> /dev/null; then
    echo "La dirección IP $ip_address está activa."
else
    echo "La dirección IP $ip_address no está activa. El escaneo no puede continuar."
    exit 1
fi

# Función para realizar escaneo TCP
function scan_tcp {
    echo "Realizando escaneo de Nmap TCP en la dirección IP: $ip_address"
    sudo nmap -p- -open --min-rate=5000 -vvv -Pn -O -oG scan_output_tcp.txt $ip_address

    # Extraer puertos abiertos del informe de Nmap TCP
    #open_ports_tcp=$(grep -oP '\d+/(open)' scan_output_tcp.txt | cut -d '/' -f 1)
    open_ports_tcp=$(grep -oP '\d+/(open)' scan_output_tcp.txt | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

    # Verificar si hay puertos abiertos TCP
    if [ -z "$open_ports_tcp" ]; then
        echo "No se encontraron puertos TCP abiertos en el escaneo."
    else
        echo "Puertos TCP abiertos encontrados: $open_ports_tcp"
        # Realizar un escaneo exhaustivo de versiones en los puertos abiertos TCP
        echo "Realizando un escaneo exhaustivo de versiones en los puertos TCP abiertos:"
        sudo nmap -sCV -p $open_ports_tcp $ip_address | tee tcp_service_versions.log
        echo "Realizando un escaneo de vulnerabilidades para los puertos TCP abiertos:"
        sudo nmap -sV -p $open_ports_tcp --script=vulscan/vulscan.nse $ip_address | tee tcp_service_vulnerabilities.log
    fi
}

# Función para realizar escaneo UDP
function scan_udp {
    echo "Realizando escaneo de Nmap UDP en la dirección IP: $ip_address"
    sudo nmap -p- -open --min-rate=5000 -vvv -Pn -sU -oG scan_output_udp.txt $ip_address

    # Extraer puertos abiertos del informe de Nmap UDP
    #open_ports_udp=$(grep -oP '\d+/(open)' scan_output_udp.txt | cut -d '/' -f 1)
    open_ports_udp=$(grep -oP '\d+/(open)' scan_output_udp.txt | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

    # Verificar si hay puertos abiertos UDP
    if [ -z "$open_ports_udp" ]; then
        echo "No se encontraron puertos UDP abiertos en el escaneo."
    else
        echo "Puertos UDP abiertos encontrados: $open_ports_udp"
        # Realizar un escaneo exhaustivo de versiones en los puertos abiertos UDP
        echo "Realizando un escaneo exhaustivo de versiones en los puertos UDP abiertos:"
        sudo nmap -sCUV -p $open_ports_udp $ip_address | tee udp_service_versions.log
        echo "Realizando un escaneo de vulnerabilidades para los puertos UDP abiertos:"
        sudo nmap -sUV -p $open_ports_udp --script=vulscan/vulscan.nse $ip_address | tee udp_service_vulnerabilities.log
    fi
}

# Permitir al usuario elegir entre escaneo TCP, UDP o ambos
echo "Dele al enter y luego ponga el número de la opción deseada"
options=("TCP" "UDP" "Ambos")
select opt in "${options[@]}"
do
    case $opt in
        "TCP")
            scan_tcp
            break
            ;;
        "UDP")
            scan_udp
            break
            ;;
        "Ambos")
            scan_tcp
            scan_udp
            break
            ;;
        *) echo "Opción inválida";;
    esac
done

echo "Escaneo de Nmap completado."

