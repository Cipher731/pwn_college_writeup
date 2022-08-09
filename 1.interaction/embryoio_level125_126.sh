rm /tmp/test_out; mkfifo /tmp/test_out
rm /tmp/test_in; mkfifo /tmp/test_in
rm /tmp/peek; mkfifo /tmp/peek

cat <<EOF > /tmp/py_script
while True:
    line = input()
    chal = line.find('for: ')
    if chal > 0: 
        print(eval(line[chal+4:].strip()))
EOF

/challenge/embryoio* </tmp/test_in >/tmp/test_out &
python /tmp/py_script >/tmp/test_in </tmp/peek &
cat /tmp/test_out | tee /tmp/peek
