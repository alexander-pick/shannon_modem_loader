#!/bin/bash

# Samsung Shannon Modem Loader, Installer Script
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

function install() {
    cp -v shannon_load.py ${1}/loaders/
    cp -v shannon_postprocess.py ${1}/python/
    cp -v shannon_pal_reconstructor.py ${1}/python/
    cp -v shannon_mpu.py ${1}/python/
    cp -v shannon_scatterload.py ${1}/python/
    cp -v shannon_generic.py ${1}/python/
    cp -v shannon_structs.py ${1}/python/
    cp -v shannon_names.py ${1}/python/
    cp -v shannon_debug_traces.py ${1}/python/
    cp -v shannon_funcs.py ${1}/python/
}

if [ -z ${IDADIR} ]; then 

    if [ -z ${1} ]; then

        if [ -d "${HOME}/idaarm-8.4" ]; then
            IDADIR="${HOME}/idaarm-8.4"
            IDABIN=ida64
        elif [ -d "${HOME}/idapro-8.4" ]; then
            IDADIR="${HOME}/idapro-8.4"
            IDABIN=ida
        elif [ -d "${HOME}/idapro-8.3" ]; then
            IDADIR="${HOME}/idapro-8.3"
            IDABIN=ida
        else 
            echo "IDA Pro not found, please install manually!"
            exit 0
        fi

    else 

        IDADIR=${1}

        if [ -z ${2} ]; then
            IDABIN=ida
        else
            IDABIN=${2}
        fi
    fi

fi

install ${IDADIR}

${IDADIR}/${IDABIN}

