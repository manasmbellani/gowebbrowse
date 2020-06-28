# gowebbrowse
Golang script that accepts YAML files which contain instructions to open URLs, or perform searches on certain websites.

## Example
To run a check for any assets in Shodan for company: `Example` with domain: `example.com`, we setup the following file: `ssh_open_ports.yaml`.
```
# ssh_open_ports.yaml
id: "ssh_open_ports"
checks:
    - type: "shodan"
      search:
        - "port:22 org:{company}"
        - "port:22 hostname:{domain}"
      notes: >
        Reports open SSH ports that could be easily accessible with simple username/password
```

Then, we run the search on Shodan.io with the following command:
```
$ go run gowebbrowse.go -s /opt/athena-tools-private/pentest_lowhanging/webbrowse_templates/ssh_open_ports.yaml -d example.com -c example
```

This will open the default browser tabs with searches listed in YAML signature file above run in `shodan.io`.