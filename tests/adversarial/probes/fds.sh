# Inherited descriptors and the broker channel.
. /probes/lib.sh
python3 /probes/fds.py || BREACHES=$((BREACHES + 1))
finish
