#gdb /usr/bin/bash <pid> --batch -x <this file>

set variable $foo = (char **) environ
set $i = 0
while ($foo[$i] != 0)
print $foo[$i++]
end
