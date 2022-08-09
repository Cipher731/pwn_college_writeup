rm /tmp/test_out
rm /tmp/test_in
mkfifo /tmp/test_in
mkfifo /tmp/test_out
echo sfvhllnm > /tmp/test_in &
/challenge/embryoio_level92 </tmp/test_in >/tmp/test_out &
cat /tmp/test_out