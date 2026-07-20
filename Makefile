# WIDS developer shortcuts (run from wids/)
.PHONY: test eval demo status lint-ci prep-demo

test:
	pytest -q

eval:
	python -m src.eval_main

demo:
	python -m src.demo_main

prep-demo:
	bash scripts/prep_demo.sh

status:
	python -m src.status_main --no-ssh

# What CI runs
lint-ci: test eval
