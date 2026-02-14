# NSLOOK

like nslookup, but with fewer features!

supports:
* A and AAAA records
* retries: see `SOCKET_TIMEOUT_SECONDS` and `SOCKET_TIMEOUT_RETRIES` in [main.h](main.h)

## Compile

```bash
gcc main.c -o nslook
```

## Run

```bash
./nslook <input_file> <output_file> [optional nameserver] [optional record type]
```

*if you want to specify record type, you must specify nameserver

### Example

```bash
./nslook input.txt output.txt
```

```bash
./nslook input.txt output.txt 8.8.8.8 A
```

```bash
./nslook input.txt output.txt 8.8.8.8 AAAA
```

## Fun Fact!
According to the RFC of DNS, you can send multiple questions in the same query!

No server supports this feature, so don't try it...