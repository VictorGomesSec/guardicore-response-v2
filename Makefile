# Makefile for Lumu Integration
MY_BASH = $(shell which bash)
MY_PWD = $(shell pwd)
MY_VENV = .venv

FILE_PATH := ".integration-name"
DEFAULT_NAME := "integration"

FIRST_LINE := $(shell if [ -s "$(FILE_PATH)" ]; then head -n 1 "$(FILE_PATH)"; fi)
NAME := $(if $(strip $(FIRST_LINE)),$(FIRST_LINE),$(DEFAULT_NAME))

container_name = lumu-$(NAME)
image_name = img-$(container_name)
RUN=docker run -v ./companies.yml:/app/companies.yml -v ./integrations.yml:/app/integrations.yml -d --restart unless-stopped --log-driver json-file --log-opt max-size=30m --log-opt max-file=3

.PHONY:  docker-pre docker-build-force docker-build \
docker-run docker-run-build docker-run-build-force docker-clear-env docker-clean-vendor \
docker-start docker-stop docker-restart docker-reset \
docker-delete docker-support docker-reset-force docker-debug docker-errors docker-ps \
docker-logs docker-fix-sudo docker-cache-last-register-clear \
sh-debug sh-errors sh-install-all sh-logs \
sh-restart-all sh-support sh-uninstall-all system sh-cache-last-register-clear \
sh-ps sh-clean-vendor config

system:
	@uname -a
	@echo "Docker Image Name: $(image_name)"
	@echo "Docker Container Name: $(container_name)"

sh-install-all: companies integrations
	chmod +x install.sh
	$(MY_BASH) install.sh all

sh-restart-all:
	chmod +x restart.sh
	$(MY_BASH) restart.sh all

sh-uninstall-all:
	chmod +x uninstall.sh
	$(MY_BASH) uninstall.sh all

sh-support:
	@echo "Creating Support file support.log"
	@echo "Dumping companies.yml file" > support.log
	@cat companies.yml >> support.log
	@echo "Dumping integrations.yml file" >> support.log
	@cat integrations.yml >> support.log
	@echo "Dumping Python Version" >> support.log
	@$(MY_PWD)/$(MY_VENV)/bin/python --version >> support.log
	@echo "Dumping PWD" >> support.log
	@pwd >> support.log
	@echo "Dumping ls -la" >> support.log
	@ls -la >> support.log
	@echo "Dumping last logs" >> support.log
	@[ -f "lumu.log" ] && tail -n 500 lumu.log >> support.log || echo "NOT FOUND lumu.log files"
	@echo "Dumping last errors" >> support.log
	@[ -f "errors.log" ] && tail -n 500 errors.log >> support.log || echo "NOT FOUND errors files"
	@echo "Dumping json files" >> support.log
	@cat .*.json >> support.log || echo "NOT FOUND json files"
	@echo "Dumping TAR File" >> support.log
	@[ -d "debug" ] && tar -cvf support.tar debug support.log || tar -cvf support.tar support.log
	@echo "Finished Support file, support.tar file was created, please send to the Lumu support. "
	@du -h support.tar

sh-debug:
	$(MY_PWD)/$(MY_VENV)/bin/python $(MY_PWD)/run.py -v || echo "Something wrong, debug did not run"

sh-logs:
	@tail -f lumu.log

sh-errors:
	@tail -n 100 errors.log

sh-clean-vendor:
	$(MY_PWD)/$(MY_VENV)/bin/python $(MY_PWD)/run.py --clean || echo "Something wrong, clean did not run"

sh-ps:
	@ps aux  | grep -i $(MY_PWD) | grep -v grep | awk '{print "PID="$$2 " - START="$$9 " - TIME="$$10 " - CMD="$$11" " $$NF}'

sh-cache-last-register-clear:
	@echo "Cleaning cache last registers"
	@rm -rf $(MY_PWD)/.last_register_file.json || echo "Something wrong, Mapping cache did not clear"

docker-pre:
	@docker -v
	@docker ps 1> /dev/null

config:
	@chmod +x ./applib/tui
	@chmod +x ./config
	@./config

integrations: integrations.yml
	@echo "Verifying integrations.yml file exist"

companies: companies.yml
	@echo "Verifying companies.yml file exist"

docker-build: docker-pre integrations companies
	docker build --tag $(image_name) --file DockerfileAllInOne .

docker-build-force: docker-pre integrations companies
	docker build --no-cache --tag $(image_name) --file DockerfileAllInOne .

docker-run-build: docker-build docker-run


docker-run-build-force: docker-build-force docker-run

docker-run:
	@$(RUN) --name $(container_name) $(image_name)
	@docker ps -l

docker-clean-vendor:
	docker exec $(container_name) python /app/run.py --clean || echo "Something wrong, clean did not run"

docker-stop:
	docker stop $(container_name)

docker-start:
	docker start $(container_name)

docker-restart: docker-stop docker-start

docker-delete: docker-clean-vendor
	docker rm -f $(container_name)

docker-clear-env: docker-delete
	docker rmi -f $(image_name)

docker-reset: docker-clear-env docker-run-build

docker-reset-force: docker-clear-env docker-run-build-force

docker-support:
	@echo "Creating Support file support.log"
	@echo "Dumping companies.yml file" > support.log
	@cat companies.yml >> support.log
	@echo "Dumping integrations.yml file" >> support.log
	@cat integrations.yml >> support.log
	@echo "Dumping Python Version" >> support.log
	@docker exec $(container_name) python --version >> support.log
	@echo "Dumping PWD" >> support.log
	@docker exec $(container_name) pwd >> support.log
	@echo "Dumping ls -la" >> support.log
	@docker exec $(container_name) ls -la >> support.log
	@echo "Dumping last logs" >> support.log
	@docker logs -n 500 $(container_name) 2>> support.log 1> /dev/null
	@echo "Dumping last errors" >> support.log
	@docker exec $(container_name) tail -n 500 errors.log >> support.log || echo "NOT FOUND errors files"
	@echo "Dumping json files" >> support.log
	@docker exec $(container_name) /bin/sh -c 'cat .*.json' >> support.log || echo "NOT FOUND json files"
	@echo "Dumping TAR File" >> support.log
	@[ -d "debug" ] && tar -cvf support.tar debug support.log || tar -cvf support.tar support.log
	@echo "Finished Support file, support.tar file was created, please send to the Lumu support. "
	@du -h support.tar

docker-debug:
	@docker exec $(container_name) python /app/run.py -v || echo "Something wrong, debug did not run"

docker-logs:
	@docker logs -f --since 30m $(container_name)

docker-errors:
	@docker exec $(container_name) tail -n 500 errors.log || echo "NOT FOUND errors files"

docker-ps:
	@docker container ps -a --no-trunc -f name=$(container_name)
	@docker container stats $(container_name)  --no-trunc --no-stream
	@docker container top $(container_name)

docker-fix-sudo:
	@echo user: $(USER) home: $(HOME)
	sudo groupadd docker || echo "Group docker already exists"
	sudo usermod -aG docker $(USER)
	sudo chown $(USER):$(USER) $(HOME)/.docker -R || echo "No such file or directory exist yet"
	sudo chmod g+rwx $(HOME)/.docker -R || echo "No such file or directory exist yet"
	@echo "Please logout and login again to apply the changes, it might be necessary to restart your computer."

docker-cache-last-register-clear:
	@echo "Cleaning cache session in Docker Container"
	@docker exec $(container_name) /bin/sh -c 'ls -la /app/.last_register_file.json' || echo "No such file or directory"
	@docker exec $(container_name) /bin/sh -c 'rm -rf /app/.last_register_file.json' || echo "Something wrong, Session cache did not clear"

docker-copy-update-package:
	@echo "Copying package to Docker Container"
	@echo "run.py ioc_manager.py applib lumudblib lumulib utils"  | tr -d "\r" | xargs -n 1 | xargs  -I {} docker cp {} $(container_name):/app
	@docker restart $(container_name)