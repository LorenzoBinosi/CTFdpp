lint:
	ruff check --select E,F,W,B,C4,I --ignore E402,E501,E712,B904,B905,I001 --exclude=CTFdpp/uploads CTFdpp/ migrations/ tests/
	isort --profile=black --check-only --skip=CTFdpp/uploads --skip-glob **/node_modules CTFdpp/ tests/
	yarn --cwd CTFdpp/themes/admin lint
	black --check --diff --exclude=CTFdpp/uploads --exclude=node_modules .
	prettier --check 'CTFdpp/themes/*/assets/**/*'
	prettier --check '**/*.md'

format:
	isort --profile=black --skip=CTFdpp/uploads --skip-glob **/node_modules CTFdpp/ tests/
	black --exclude=CTFdpp/uploads --exclude=node_modules .
	prettier --write 'CTFdpp/themes/**/assets/**/*'
	prettier --write '**/*.md'

test:
	pytest -rf --cov=CTFdpp --cov-context=test --cov-report=xml \
		--ignore-glob="**/node_modules/" \
		--ignore=node_modules/ \
		-W ignore::sqlalchemy.exc.SADeprecationWarning \
		-W ignore::sqlalchemy.exc.SAWarning \
		-n auto
	bandit -r CTFdpp -x CTFdpp/uploads --skip B105,B322
	pipdeptree

coverage:
	coverage html --show-contexts

serve:
	python serve.py

shell:
	python manage.py shell
