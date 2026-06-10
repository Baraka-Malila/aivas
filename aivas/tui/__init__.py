__all__ = ["AIVASApp"]


def __getattr__(name: str):
    if name == "AIVASApp":
        from .app import AIVASApp
        return AIVASApp
    raise AttributeError(name)
