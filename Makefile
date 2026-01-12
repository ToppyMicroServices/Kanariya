.PHONY: dev test smoke

dev:
	wrangler dev

test:
	npm test

smoke:
	BASE_URL=$${BASE_URL} TOKEN=$${TOKEN} ADMIN_KEY=$${ADMIN_KEY} ./scripts/smoke_test.sh
