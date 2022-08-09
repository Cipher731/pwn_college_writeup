/challenge/emb* >&/dev/null &

exec 33<>/dev/tcp/127.0.0.1/1152

cat <<EOF > /tmp/py_script
import sys

line = sys.argv[1]
chal = line.find('for: ')
if chal > 0: 
    print(eval(line[chal+4:].strip()))
EOF

while read line;
do
    echo "$line"
    python /tmp/py_script "$line" >&33
done <&33 
