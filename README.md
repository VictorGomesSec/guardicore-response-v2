
## 1. The IOC Management

### companies.yml File

```yaml
-
  lumu:
    uuid: "COMPANY_UUID"
    defender_key: "DEFENDER_API_KEY"
    hash_type: "sha256" # sha256 | sha1 | md5
    ioc_types: # list of ioc types, option one, many or all
      - ip
    adversary:  # list of adversary types, option one, many or all
      - C2C
      - Malware
      - Mining
      - Spam
      - Phishing
      - Anonymizer
    days: 3 # MIN 1, MAX 3
-
  COMPANY 3
-
  COMPANY 4
-
  ...
```

### Script execution

```properties
python ioc_manager.py --help
usage: ioc_management_lumu [-h] [--config CONFIG] [-v] [-l {screen,file}] [--hours HOURS] [--days-intervals DAYS_INTERVALS]

Lumu Custom IOC management: Main Process

options:
  -h, --help            show this help message and exit
  --config CONFIG       default: companies.yml, CONFIG FILE PATH of the companies, follow the nex YML template.
  -v, --verbose         the flag means DEBUG mode, by default is INFO mode
  -l {screen,file}, --logging {screen,file}
                        logs output on commandline or file.
  --hours HOURS         keep db log record from [x hours], for auto maintenance local db purpose
  --days-intervals DAYS_INTERVALS
                        how often the complete search and retrieve of Lumu IOC will be made

Please complete all parameter to run

```

## 2. Third Party Integration (APP)

### integration.yml File (Public Version)

```yaml

- lumu:
    uuid: "COMPANY-UUID"
    days: 3
  app:
    name: "UNIQUE-NAME"
    rule_set: "RULE-SET-NAME" # Case Sensitive, e.g. "LumuClientARuleSet"
    api:
      url_management_server: "URL-MANAGEMENT-SERVER" #  "https://Hostname|FQDN|IPAddress[:Port]/"
      username: "USERNAME"
      password: "PASSWORD"
```

### integrations.yml File (full internal version)

```yaml
- lumu:
    uuid: "COMPANY-UUID"
    adversaryTypes: [ "C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"] # ["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"]
    days: 3
  app:
    name: "UNIQUE-NAME"
    clean: false # true | false
    rule_set: "RULE-SET-NAME" # Case Sensitive, e.g. "LumuClientARuleSet"
    rule_id: "RULE-ID" # e.g. "RUL-C3305F6C"
    ioc: ["ip"] # Optional, default [ "ip" ]
    provisioning: true # true | false
    max: MAX-INDICATORS # max 5000
    api:
      url_management_server: "URL-MANAGEMENT-SERVER" #  "https://Hostname|FQDN|IPAddress[:Port]/"
      username: "USERNAME"
      password: "PASSWORD"
- INTEGRATION 2
- INTEGRATION 3
-  ...
```

### Script execution

```shell
python run.py --help
                                                                                                                                                                                                      
 Usage: run.py [OPTIONS]                                                                                                                                                                              
                                                                                                                                                                                                      
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --verbose              -v                     Enable verbose mode.                                                                                                                                 │
│ --clean                                       Clean all integrations and override the yml clean field.                                                                                             │
│ --logging-type         -l      [screen|file]  Logging output type: 'screen' or 'file' [default: screen]                                                                                            │
│ --config                       TEXT           Path to the configuration file. [default: integrations.yml]                                                                                          │
│ --ioc-manager-db-path          TEXT           Path to the IOC manager database file. [default: ./ioc.db]                                                                                           │
│ --help                                        Show this message and exit.                                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯



```

## Installation via Bash script

Only Debian/Ubuntu Distribution supported
- Debian 12.x
- Ubuntu 20.x, 22.x


### prerequisites

* sudo service and sudores user enabled for the installation
* disable ipv6 service or set ipv4 preferences over ipv6
* execution permission upon the `install.sh`, `uninstall.sh` and `restart.sh` script files

### Execution 

`./install.sh all`, `./uninstall.sh all` and `./restart.sh all`


## Deploy in Docker (optional)

### Deployment

- run the command over the `root` directory

#### Build & Run Container the App Integration (it means an IOC Manager must already exist)

`docker build [--build-arg APP_CONFIG='integrations.yml'] --tag img-lumu-guardicore-response --file Dockerfile .`

`docker run -d --restart unless-stopped -v <IOC-DB-FULL-PATH>:/db/ioc.db --name lumu-guardicore-response img-lumu-guardicore-response`

- example:

`docker build --build-arg APP_CONFIG='integrations.yml' --tag img-lumu-guardicore-response --file Dockerfile .`

`docker run -d --restart unless-stopped -v ./ioc.db:/db/ioc.db --name lumu-guardicore-response img-lumu-guardicore-response`


_**Note:** Do not forget the dot "."_

#### Build & Run Container the AppIntegration and an IOC Manager All in One Docker container

##### Build

`docker build [--build-arg IOC_MAN_CONFIG='companies.yml'] [--build-arg APP_CONFIG='integrations.yml'] --tag img-lumu-guardicore-response --file DockerfileAllInOne .`

`docker build --tag img-lumu-guardicore-response --file DockerfileAllInOne .`

_**Note:** Do not forget the dot "."_

##### Run

`docker run -v ./companies.yml:/app/companies.yml -v ./integrations.yml:/app/integrations.yml -d --restart unless-stopped --log-driver json-file --log-opt max-size=30m --log-opt max-file=3 --name lumu-guardicore-response img-lumu-guardicore-response`


`docker run -d \
-v ./companies.yml:/app/companies.yml \
-v ./integrations.yml:/app/integrations.yml \
--restart unless-stopped \
--log-driver json-file \
--log-opt max-size=30m \
--log-opt max-file=3 \
--name lumu-guardicore-response \
img-lumu-guardicore-response`




#### Logs

`docker logs -f lumu-guardicore-response`

#### Interactive console

`docker exec -it lumu-guardicore-response bash`


### Deploy via MAkE

- Run the integration
  `make docker-run-build`
- show logs
  `make docker-logs`


List of commands

```shell
make 
companies                            docker-debug                         docker-reset-force                   integrations                         sh-ps
docker-build                         docker-delete                        docker-restart                       sh-cache-last-register-clear         sh-restart-all
docker-build-force                   docker-errors                        docker-run                           sh-cache-web-address-rule-clear      sh-support
docker-cache-last-register-clear     docker-fix-sudo                      docker-run-build                     sh-clean-vendor                      sh-uninstall-all
docker-cache-web-address-rule-clear  docker-logs                          docker-run-build-force               sh-debug                             system
docker-clean-vendor                  docker-pre                           docker-start                         sh-errors                            
docker-clear-env                     docker-ps                            docker-stop                          sh-install-all                       
docker-copy-update-package           docker-reset                         docker-support                       sh-logs  
```

### COMMON ERRORS
