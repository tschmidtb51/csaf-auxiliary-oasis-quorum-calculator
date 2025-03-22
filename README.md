# oasis-quorum-calculator

:warning: **This is work in progress!**

A simple tool to calculate the quorum for OASIS TCs (definitely JavaScript-free)


Build
```shell
make
```

Create an initial config file.
```shell
cp docs/example-oqcd.toml oqcd.toml
```

Do the initial database migration.
```shell
OQC_DB_MIGRATE=true ./bin/oqcd
```

Extract the password of `admin`. Use it to log in.
```shell
sed -En 's/.*user=admin.+password=([0-9a-zA-Z]+).*/\1/p' oqcd.log
```

The sessions are signed with a key.
To have sessions that survive restaring oqcd
you need to store the signing secret into the config file.
```shell
SECRET=`sed -En 's/.*session key.+secret=([[:xdigit:]]+).*/\1/p' oqcd.log`
sed -i -e 's/^#secret =.*/secret = "'$SECRET'"/' -e 's/^#\[sessions\]/[sessions]/' oqcd.toml
```

Starting
```shell
./bin/oqcd
```
