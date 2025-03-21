# oasis-quorum-calculator

:warning: **This is work in progress!**

A simple tool to calculate the quorum for OASIS TCs (definitely JavaScript-free)


```bash
go build ./cmd/...

echo -e '[database]\nmigrate = true' > oqcd.toml
./oqcd
tail oqcd.log

echo -e '[database]\nmigrate = false' > oqcd.toml
./oqcd &
sleep 1
tail -1 oqcd.log
```
