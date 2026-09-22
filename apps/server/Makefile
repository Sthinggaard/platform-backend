SHELL := /bin/sh
include ../../config/local-ports.env
export RISKLENCE_LOCAL_API_PORT
LOCAL_API_ENV := API_PORT=$(RISKLENCE_LOCAL_API_PORT) DATABASE__POSTGRES_PORT=$(RISKLENCE_LOCAL_POSTGRES_PORT) DATABASE__MONGODB_URI=mongodb://localhost:$(RISKLENCE_LOCAL_MONGODB_PORT) REDIS_URL=redis://localhost:$(RISKLENCE_LOCAL_REDIS_PORT)/0 APP_BASE_URL=http://localhost:$(RISKLENCE_LOCAL_API_PORT) FRONTEND_BASE_URL=$(FRONTEND_BASE_URL) AUTH0_CALLBACK_URL=$(AUTH0_CALLBACK_URL) SSO_CALLBACK_URL=$(SSO_CALLBACK_URL)

.PHONY: api-dev db-check

api-dev:
	$(LOCAL_API_ENV) DEBUG=false MONITORING_ENABLED=false poetry run uvicorn src.api.main:app --reload --port $(RISKLENCE_LOCAL_API_PORT)

db-check:
	DEBUG=false MONITORING_ENABLED=false poetry run python -c 'from sqlalchemy import text; from src.core.database import get_postgres_engine; engine = get_postgres_engine(); conn = engine.connect(); row = conn.execute(text("select current_user, current_database()")).fetchone(); print(row); conn.close()'
