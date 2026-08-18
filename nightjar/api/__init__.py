"""FastAPI app serving the Nightjar dashboard and its JSON API."""

from .app import create_app

__all__ = ["create_app"]
