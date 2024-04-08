#!/bin/bash

if [ -z ${IDADIR} ]; then  

    if [ -d "${HOME}/idapro-8.3" ]; then
        IDADIR="${HOME}/idapro-8.3"
    elif [ -d "${HOME}/idapro-8.4" ]; then
        IDADIR="${HOME}/idapro-8.4"
    else 
        echo "IDA Pro not found, please install manually!"
        exit 0
    fi

fi

cp shannon_load.py ${IDADIR}/loaders/
${IDADIR}/ida