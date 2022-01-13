# Commands

**Install and run sigma converter**

```sh
$ cd sigma\tools
$ python setup.py install
$ cd ../
$ python ./sigmac.py -t splunk -c tools/config/generic/sysmon.yml ./rules/windows/process_creation/win_susp_whoami.yml
```

**Sigma  Generate MITRE Heat Map from your own use cases repo**

```sh
$ python sigma\tools\sigma\sigma2attack.py -d sigma_rules\. -o HeatMap.json
```

