.PHONY: dev clean

PYTHON = python3
VENV = .venv

dev: $(VENV)/bin/activate
	source $(VENV)/bin/activate && pip install --upgrade pip && pip install -e . uvicorn && uvicorn control_plane_api.main:app --reload

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)

clean:
	rm -rf $(VENV)