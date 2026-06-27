.PHONY: init build certs up down logs wait clean \
	restart-vouch vouch-logs \
	test-oidc-basic test-oidc-config test-oidc-dynamic test-oidc-formpost \
	test-oidc-rp-logout \
	test-fapi2 test-fapi2-sp-mtls-mtls test-fapi2-sp-mtls-dpop \
	test-fapi2-sp-pk-mtls \
	test-fapi2-ms test-fapi2-ms-jarm \
	test-fapi2-ms-mtls test-fapi2-ms-mtls-jarm \
	test-fapi2-all-sp test-fapi2-all-ms test-fapi2-all \
	test-all rerun-failures

CONFORMANCE_SERVER ?= https://localhost.emobix.co.uk:8443
VOUCH_URL          ?= https://localhost:9443
SCRIPTS            := scripts
CONFIG             := config
PYTHON             := .venv/bin/python

$(PYTHON):
	uv sync

# -- Setup --------------------------------------------------------------------

init:
	git submodule update --init --recursive

certs:
	@mkdir -p certs
	@test -f certs/vouch.crt || \
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
			-keyout certs/vouch.key \
			-out certs/vouch.crt \
			-subj "/CN=vouch" \
			-addext "subjectAltName=DNS:vouch,DNS:localhost" \
			2>/dev/null && \
		echo "Generated certs/vouch.crt"
	@test -f certs/vouch-tls.env || { \
		echo "VOUCH_TLS_CERT=$$(base64 < certs/vouch.crt | tr -d '\n')" > certs/vouch-tls.env && \
		echo "VOUCH_TLS_KEY=$$(base64 < certs/vouch.key | tr -d '\n')" >> certs/vouch-tls.env && \
		echo "Generated certs/vouch-tls.env"; \
	}
	@test -f certs/nginx.crt || \
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
			-keyout certs/nginx.key \
			-out certs/nginx.crt \
			-subj "/CN=localhost" \
			-addext "basicConstraints=critical,CA:FALSE" \
			-addext "subjectAltName=DNS:localhost,DNS:nginx,DNS:localhost.emobix.co.uk" \
			2>/dev/null && \
		echo "Generated certs/nginx.crt"

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
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan oidcc-basic-certification-test-plan \
		--config $(CONFIG)/oidcc-basic.json

test-oidc-config:
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan oidcc-config-certification-test-plan \
		--config $(CONFIG)/oidcc-config.json

test-oidc-dynamic:
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan oidcc-dynamic-certification-test-plan \
		--config $(CONFIG)/oidcc-dynamic.json

test-oidc-formpost:
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan oidcc-formpost-basic-certification-test-plan \
		--config $(CONFIG)/oidcc-formpost.json

test-oidc-rp-logout:
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan oidcc-rp-initiated-logout-certification-test-plan \
		--config $(CONFIG)/oidcc-rp-logout.json

# -- FAPI 2.0 Security Profile (columns 1-5) ----------------------------------

test-fapi2-sp-mtls-mtls:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-mtls.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-mtls.json

test-fapi2-sp-mtls-dpop:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-dpop.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-mtls-dpop.json

test-fapi2-sp-pk-mtls:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-pk-mtls.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-sp-pk-mtls.json

test-fapi2:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-security-profile.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-security-profile-final-test-plan \
		--config $(CONFIG)/fapi2-security-profile.json

# -- FAPI 2.0 Message Signing (columns 6-7) -----------------------------------

test-fapi2-ms:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-message-signing.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-message-signing.json

test-fapi2-ms-jarm:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-jarm.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-jarm.json

test-fapi2-ms-mtls:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-mtls.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-mtls.json

test-fapi2-ms-mtls-jarm:
	@eval "$$($(PYTHON) $(SCRIPTS)/register_client.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-mtls-jarm.json)" && \
	$(PYTHON) $(SCRIPTS)/run.py \
		--plan fapi2-message-signing-final-test-plan \
		--config $(CONFIG)/fapi2-ms-mtls-jarm.json

# -- FAPI 2.0 grouping targets ------------------------------------------------

test-fapi2-all-sp: test-fapi2-sp-mtls-mtls test-fapi2-sp-mtls-dpop \
	test-fapi2-sp-pk-mtls test-fapi2

test-fapi2-all-ms: test-fapi2-ms test-fapi2-ms-jarm \
	test-fapi2-ms-mtls test-fapi2-ms-mtls-jarm

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
	$(PYTHON) $(SCRIPTS)/run.py --rerun-failures \
		--plan $$(python3 -c "import json; print(json.load(open('.last-run.json'))['plan_name'])") \
		--config $$(python3 -c "import json; s=json.load(open('.last-run.json')); print(s.get('config',''))")

# -- Run all -------------------------------------------------------------------

test-all: test-oidc-basic test-oidc-config test-oidc-dynamic test-oidc-formpost test-oidc-rp-logout test-fapi2-all
