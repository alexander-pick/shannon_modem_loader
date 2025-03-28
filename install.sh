#!/bin/bash

# Samsung Shannon Modem Loader, Installer Script
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024-2025

declare -a IDADIRA=("ida-essential-9.0" "ida-pro-9.0" "ida-home-arm-9.0" "idaarm-8.4" "idaarm-8.3" "idapro-8.4" "idapro-8.3")
declare -a IDABINA=("ida" "ida" "ida" "ida64" "ida64" "ida64" "ida")

echo -e ""
echo "░▀█▀░█▀▄░█▀█░░░█▀▀░█▀▀░█▄█░█░░░░░▀█▀░█▀█░█▀▀░▀█▀░█▀█░█░░░█░░░█▀▀░█▀▄"
echo "░░█░░█░█░█▀█░░░▀▀█░▀▀█░█░█░█░░░░░░█░░█░█░▀▀█░░█░░█▀█░█░░░█░░░█▀▀░█▀▄"
echo "░▀▀▀░▀▀░░▀░▀░░░▀▀▀░▀▀▀░▀░▀░▀▀▀░░░▀▀▀░▀░▀░▀▀▀░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀"
echo -e "Install Samsung Shannon Modem Loader, 2024-2025 by Alexander Pick"
echo -e "https://github.com/alexander-pick/shannon_modem_loader\n"

function help() {
    echo -e "commandline options:"
    echo -e "-d <dir> specify IDA installation directory"
    echo -e "-r run IDA after installation"
    echo -e "-a auto mode, find IDA installation dir automatically"
    echo -e "-t test mode, combines -a -r and enabled logging in IDA"
    echo -e "-h print help"
    exit 0
}

function install() {
    echo "[i] Cleaning old Shannon plugin files..."
    rm -f ${IDADIR}/python/shannon_*.py
    rm -f ${IDADIR}/loaders/shannon_load.py

    echo "[i] Installing updated files..."
    cp -v shannon_load.py ${IDADIR}/loaders/
    cp -v shannon_postprocess.py ${IDADIR}/python/
    cp -v shannon_pal_reconstructor.py ${IDADIR}/python/
    cp -v shannon_mpu.py ${IDADIR}/python/
    cp -v shannon_scatterload.py ${IDADIR}/python/
    cp -v shannon_generic.py ${IDADIR}/python/
    cp -v shannon_structs.py ${IDADIR}/python/
    cp -v shannon_names.py ${IDADIR}/python/
    cp -v shannon_debug_traces.py ${IDADIR}/python/
    cp -v shannon_funcs.py ${IDADIR}/python/
    cp -v shannon_indirect_xref.py ${IDADIR}/python/

    cp -v sig/*.sig ${IDADIR}/sig/arm/
}


function findIDA() {
    if [ -z ${IDADIR} ]; then 

        if [ -z ${1} ]; then

            ALEN=${#IDADIRA[@]}

            # use for loop to read all values and indexes
            for (( i=0; i<${ALEN}; i++ ));
            do
                echo -e "[i] checking for ${IDADIRA[$i]}"
                if [ -d "${HOME}/${IDADIRA[$i]}" ]; then

                    IDADIR="${HOME}/${IDADIRA[$i]}"
                    IDABIN=${IDABINA[$i]}

                    echo -e "[i] found - installing and starting ${IDABINA[$i]}"
                    break
                
                fi
            done

        else 

            IDADIR=${1}

            if [ -z ${2} ]; then
                IDABIN=ida
            else
                IDABIN=${2}
            fi
        fi

    else 
        echo -e "[i] IDADIR env is set, overriding commandline selection"

    fi
}

function run_IDA() {

    IDADEBUGLOG="/tmp/ida_shannon.log"

    rm -f ${IDADEBUGLOG}
    touch ${IDADEBUGLOG}

    # -z3003 - for performance issues

    eval "${IDADIR}/${IDABIN}  -L${IDADEBUGLOG} &"
    tail -f ${IDADEBUGLOG}
    
    exit 0
}

while getopts d:b:rath FLAG
do
    case "${FLAG}" in
        d) IDADIR_OPT=${OPTARG};;
        b) IDABIN_OPT=${OPTARG};;
        r) IDARUN_OPT=1;;
        a) IDAAUTO_OPT=1;;
        t) IDATEST_OPT=1;;
        h) help;;
    esac
done

if [ -n "${IDATEST_OPT}" ]; then

    echo -e "[i] running in auto test mode"
    findIDA
    install
    echo -e "[i] starting IDA with logging"

    run_IDA
fi

if [ -z "${IDAAUTO_OPT}" ]; then
    if [ -z "${IDADIR_OPT}" ]; then
        help
    fi
fi

findIDA ${IDADIR_OPT} ${IDABIN_OPT}
echo -e "[i] IDA at ${IDADIR}/${IDABIN}"

install
echo -e "[i] installation done"

if [ -n "${IDARUN_OPT}" ]; then
    echo -e "[i] starting IDA"

    run_IDA
fi