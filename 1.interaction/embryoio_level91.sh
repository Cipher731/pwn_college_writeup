rm /tmp/test
mkfifo /tmp/test
/challenge/embryoio_level91 > /tmp/test &
cat /tmp/test