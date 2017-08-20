#!/bin/bash

_ARG_MAKE_SET=0
_ARG_SERVER_SET=0
_ARG_DEVICE_SET=0

function run_server() {
    nfd-stop
    nohup nfd-start &
    sleep 1
    ./server.app $@
}

function run_device() {
    nfd-stop
    nohup nfd-start &
    sleep 1
    ./device.app $@
}

for i in "$@"
do
case $i in
    -S|--server)
        shift
	run_server $@ && exit
        ;;
    -D|--device)
        shift
	run_device $@ && exit
        ;;
    -m|--make)
        bash /vagrant/VagrantCommand.sh -s && make all
        shift # past argument=value
        ;;
    *)
            # unknown option
    ;;
esac
done
