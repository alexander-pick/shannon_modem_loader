#!/bin/bash

# Samsung Shannon Modem Loader, Installer Script
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

if [ -z ${IDADIR} ]; then 

    if [ -z ${1} ]; then

        if [ -d "${HOME}/idapro-8.4" ]; then
            IDADIR="${HOME}/idapro-8.4"
        elif [ -d "${HOME}/idapro-8.3" ]; then
            IDADIR="${HOME}/idapro-8.3"
        else 
            echo "IDA Pro not found, please install manually!"
            exit 0
        fi

    else 

        IDADIR=${1}

    fi

fi

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

${IDADIR}/ida