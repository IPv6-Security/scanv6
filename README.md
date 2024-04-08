# Scanv6

An IPv6 based Internet Scanner

## Usage
`scanv6` is currently only supported in Linux based operating systems family due to socket creation parameters (such as `AF_PACKET` is not present in MacOS). Cross-platform port of the scanner might be implemented in the future.  

### Dependencies
`scanv6` uses go version `1.21+` and `gopacket` library which requires libpcap header files to be present. The header files and libpcap can be installed as follows:
```
$> sudo apt-get install git libpcap-dev
```

### Compiling
In order to compile the scanner, you can use the Makefile as:
```
$> make
```

If you also would like to update the all other modules, and recompile them, run the following:
```
$> make update
```
This would clean the cache and update/recompile all packages along with `scanv6`.

It is suggested to run this, when you updat your Go version.

## Usage
```
Usage:
  scanv6 [OPTIONS] <icmp6_echoscan | tcp6_synscan | udp6_dnsscan>
```

For the parameters, please run:
```
  scanv6 -h
```

### Running with a Config File (.ini files)

In order to run the scanner with a config file, you should run it with the scanner command with `--config-file` option set.
Some examples of config files per module can be found under `config/sample_conf_*.ini`.

An example of how to run the command:
```
#> ./scanv6 icmp6_echoscan --config-file config/sample_conf_icmp6.ini
```

If your module has module specific flags (such as UDP6 DNS scan module), you need to create an option block in your ini file:
```
[Application Options]
input-file="input.txt"
...
probes=1
[your_module_name]
module_specific_flag1="value1"
module_specific_flag2=value2
module_specific_flag3=true
...
```

### Simulation Mode

By default, the scanner runs in normal mode (i.e., performing an actual Internet scan). However, we do provide a simulation mode, which can be used to simulate a given hit-rate. The active hosts are chosen at random in the output module. To activate the simulation mode, the users are expected to set `--simulation=true` and choose their hit-rate with `--simulation-hitrate=YOUR_HITRATE`. `scanv6` supports hit-rates up to two decimal points. Note that this mode does not support detailed outputs for the modules.

## License
`scanv6` is licensed under Apache 2.0. For more information, see the LICENSE file.

