#!/bin/bash

_ARG_MAKE_SET=0
_ARG_SERVER_SET=0
_ARG_DEVICE_SET=0

for i in "$@"
do
case $i in
    -s|--sync)
	_ARG_SERVER_SET=1
        shift
        ;;
    -d|--delete)
        _ARG_DEVICE_SET=1
        shift
        ;;
    -m|--make)
        _ARG_MAKE_SET=1
        shift # past argument=value
        ;;
    *)
            # unknown option
    ;;
esac
done

function run_server() {
    nfd-stop
    nohup nfd-start &
    sleep 1
    ./server.app
}

function run_device() {
    nfd-stop
    nohup nfd-start &
    sleep 1
    ./device.app
}

[[ ${_ARG_MAKE_SET} -eq 1 ]] && bash /vagrant/VagrantCommand.sh -s && make all
[[ ${_ARG_SERVER_SET} -eq 1 ]] && run_server && exit
[[ ${_ARG_DEVICE_SET} -eq 1 ]] && run_device && exit
