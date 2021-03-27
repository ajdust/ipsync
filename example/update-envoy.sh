#!/bin/bash
# Find and replace a config's IP address and send quit command to Envoy admin service, assumed that Envoy service will restart.

for i in "$@"
do
case $i in
    -o=*|--old=*)
    OLD="${i#*=}"
    shift # past argument=value
    ;;
    -n=*|--new=*)
    NEW="${i#*=}"
    shift # past argument=value
    ;;
    *)
          # unknown option
    ;;
esac
done

echo "Updating ./config.yaml ${OLD} -> ${NEW}"
sed -i "s/${OLD}/${NEW}/g" ./config.yaml
curl -X POST 127.0.0.1:8001/quitquitquit || true
