.PHONY: init build certs up down logs wait clean \
	restart-vouch vouch-logs \
	test-oidc-basic test-oidc-implicit test-oidc-hybrid \
	test-oidc-config test-oidc-dynamic test-oidc-formpost \
	test-fapi2 test-fapi2-sp-mtls-mtls test-fapi2-sp-mtls-dpop \
	test-fapi2-sp-pk-mtls test-fapi2-ms test-fapi2-ms-jarm \
	test-fapi2-all-sp test-fapi2-all-ms test-fapi2-all \
	test-all rerun-failures

CONFORMANCE_SERVER ?= https://localhost.emobix.co.uk:8443
VOUCH_URL          ?= https://localhost:9443
VOUCH_BASE_URL     ?= https://vouch-proxy
SCRIPTS            := scripts
CONFIG             := config

# -- Setup --------------------------------------------------------------------

init:
	git submodule update --init --recursive

certs:
	@mkdir -p certs
	@test -f certs/vouch-proxy.crt || \
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
			-keyout certs/vouch-proxy.key \
			-out certs/vouch-proxy.crt \
			-subj "/CN=vouch-proxy" \
			-addext "subjectAltName=DNS:vouch-proxy,DNS:localhost" \
			2>/dev/null && \
		echo "Generated certs/vouch-proxy.crt"
	@test -f certs/vouch-tls.env || { \
		echo "VOUCH_TLS_CERT=$$(base64 < certs/vouch-proxy.crt)" > certs/vouch-tls.env && \
		echo "VOUCH_TLS_KEY=$$(base64 < certs/vouch-proxy.key)" >> certs/vouch-tls.env && \
		echo "Generated certs/vouch-tls.env"; \
	}

build: init certs
	cd conformance-suite && \
		MAVEN_CACHE=../m2 docker compose -f builder-compose.yml run --rm \
		builder mvn -B clean package -DskipTests=true -Dmaven.gitcommitid.skip=true

# -- Docker Compose -----------------------------------------------------------

up: certs
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

wait:
	@echo "Waiting for conformance suite..."
	@until curl -ksfm 5 $(CONFORMANCE_SERVER)/ >/dev/null 2>&1; do \
		sleep 5; \
	done
	@echo "Conformance suite is ready"
	@echo "Waiting for vouch server..."
	@until curl -ksfm 5 $(VOUCH_URL)/health >/dev/null 2>&1; do \
		sleep 5; \
	done
	@echo "Vouch server is ready"

clean:
	docker compose down -v --rmi local
	rm -rf certs m2 conformance-suite/target conformance-suite/mongo

# -- OIDC test plans ----------------------------------------------------------

test-oidc-basic:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-basic-certification-test-plan \
		--config $(CONFIG)/oidcc-basic.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-oidc-implicit:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-implicit-certification-test-plan \
		--config $(CONFIG)/oidcc-implicit.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-oidc-hybrid:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-hybrid-certification-test-plan \
		--config $(CONFIG)/oidcc-hybrid.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-oidc-config:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-config-certification-test-plan \
		--config $(CONFIG)/oidcc-config.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-oidc-dynamic:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-dynamic-certification-test-plan \
		--config $(CONFIG)/oidcc-dynamic.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-oidc-formpost:
	python3 $(SCRIPTS)/run.py \
		--plan oidcc-formpost-basic-certification-test-plan \
		--config $(CONFIG)/oidcc-formpost-basic.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

# -- FAPI 2.0 Security Profile (columns 1-5) ----------------------------------

test-fapi2-sp-mtls-mtls:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-mtls.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-mtls.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-fapi2-sp-mtls-dpop:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-dpop.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-dpop.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-fapi2-sp-pk-mtls:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-pk-mtls.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-pk-mtls.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-fapi2:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-security-profile.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-security-profile.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

# -- FAPI 2.0 Message Signing (columns 6-7) -----------------------------------

test-fapi2-ms:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-message-signing.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-message-signing.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

test-fapi2-ms-jarm:
	@eval "$$(python3 $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-jarm.json \
		--vouch-url $(VOUCH_URL) \
		--conformance-url $(CONFORMANCE_SERVER))" && \
	python3 $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-jarm.json \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

# -- FAPI 2.0 grouping targets ------------------------------------------------

test-fapi2-all-sp: test-fapi2-sp-mtls-mtls test-fapi2-sp-mtls-dpop \
	test-fapi2-sp-pk-mtls test-fapi2

test-fapi2-all-ms: test-fapi2-ms test-fapi2-ms-jarm

test-fapi2-all: test-fapi2-all-sp test-fapi2-all-ms

# -- Iteration helpers ---------------------------------------------------------

restart-vouch:
	docker compose up -d --build --no-deps vouch
	@echo "Waiting for vouch..."
	@until curl -ksfm 5 $(VOUCH_URL)/health >/dev/null 2>&1; do \
		sleep 2; \
	done
	@echo "Vouch restarted"

vouch-logs:
	docker compose logs -f vouch

rerun-failures:
	python3 $(SCRIPTS)/run.py --rerun-failures \
		--plan $$(python3 -c "import json; print(json.load(open('.last-run.json'))['plan_name'])") \
		--config $$(python3 -c "import json; s=json.load(open('.last-run.json')); print(s.get('config',''))") \
		--base-url $(VOUCH_BASE_URL) \
		--conformance-server $(CONFORMANCE_SERVER)

# -- Run all -------------------------------------------------------------------

test-all: test-oidc-basic test-oidc-implicit test-oidc-hybrid \
	test-oidc-config test-oidc-dynamic test-oidc-formpost test-fapi2-all
