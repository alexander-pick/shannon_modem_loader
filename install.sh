#!/bin/bash

if [ -z ${IDADIR} ]; then 

    if [ ${1} == "" ]; then

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
${IDADIR}/ida