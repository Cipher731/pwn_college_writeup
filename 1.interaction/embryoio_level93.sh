rm /tmp/test_out; mkfifo /tmp/test_out
rm /tmp/test_in; mkfifo /tmp/test_in
rm /tmp/peek; mkfifo /tmp/peek

/challenge/embryoio_level93 </tmp/test_in >/tmp/test_out &
LANG=C perl -ne 'print (eval $1) && exit if /for: (.*)\n/' >/tmp/test_in </tmp/peek &
cat /tmp/test_out | tee /tmp/peek
