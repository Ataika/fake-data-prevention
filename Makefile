.PHONY: test api frontend pipeline

test:
	python3 -m unittest discover -s tests -v

api:
	python3 api/app.py

frontend:
	cd frontend && python3 -m http.server 8080

pipeline:
	python3 main.py

